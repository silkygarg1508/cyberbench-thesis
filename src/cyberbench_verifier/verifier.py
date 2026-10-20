from __future__ import annotations

import hashlib
import json
import re
from datetime import timezone
from typing import Any

from .schemas import (
    CheckResult,
    Claim,
    ClaimJudgement,
    CyberBenchCase,
    InvestigationPlan,
    Route,
    RoutingDecision,
)


FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "attack_complexity": ("attack complexity", "complexity"),
    "attack_vector": ("attack vector",),
    "approved_change": ("approved change",),
    "cvss_score": ("cvss", "cvss score"),
    "cwe": ("cwe", "weakness"),
    "dmarc": ("dmarc",),
    "dkim": ("dkim",),
    "failed_attempts": ("failed attempts",),
    "mfa_result": ("mfa",),
    "risk_level": ("risk level", "risk"),
    "severity": ("severity",),
    "spf": ("spf",),
    "url_domain_age_days": ("domain", "domain age"),
    "url_reputation": ("reputation",),
}

ENUM_ALTERNATIVES: dict[str, tuple[str, ...]] = {
    "mfa_result": ("success", "succeeded", "denied", "failed"),
    "risk_level": ("low", "medium", "high", "critical"),
    "severity": ("low", "medium", "high", "critical"),
    "spf": ("pass", "fail", "neutral", "softfail"),
    "dkim": ("pass", "fail", "none"),
    "dmarc": ("pass", "fail", "none"),
    "url_reputation": ("benign", "suspicious", "malicious", "unknown"),
}


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_plan(case: CyberBenchCase) -> InvestigationPlan:
    return InvestigationPlan(
        steps=[
            "Read the user request and candidate recommendation.",
            "Retrieve only the frozen evidence pack.",
            "Extract material factual claims and the recommended action.",
            "Check provenance, execution, evidence values, freshness and policy.",
            "Route the case and write an append-only trace.",
        ],
        required_evidence_fields=case.agent_input.evidence_pack.evaluation_context.required_fields,
    )


ACTION_MARKERS = (
    re.compile(r"Recommended action\s*:\s*", flags=re.IGNORECASE),
    re.compile(r"Proposed next step\s*:\s*", flags=re.IGNORECASE),
    re.compile(r"Recommendation\s*:\s*", flags=re.IGNORECASE),
    re.compile(r"Action\s*:\s*", flags=re.IGNORECASE),
)


def split_candidate_response(candidate_response: str) -> tuple[str, str | None]:
    response = candidate_response.strip()
    match = next(
        (
            matches[-1]
            for marker in ACTION_MARKERS
            if (matches := list(marker.finditer(response)))
        ),
        None,
    )
    if not match:
        return response, None
    observation = response[: match.start()].strip()
    action = response[match.end() :].strip().rstrip(".")
    return observation, action or None


def extract_action(candidate_response: str) -> str | None:
    return split_candidate_response(candidate_response)[1]


def extract_claims(case: CyberBenchCase) -> list[Claim]:
    observation, action = split_candidate_response(
        case.agent_input.candidate_response
    )
    evidence_ids = [
        item.evidence_id for item in case.agent_input.evidence_pack.evidence_items
    ]
    claims = [
        Claim(
            claim_id="C1",
            text=observation,
            kind="observation",
            evidence_ids=evidence_ids,
        )
    ]
    if action:
        claims.append(
            Claim(
                claim_id="C2",
                text=action,
                kind="recommendation",
                evidence_ids=[],
            )
        )
    return claims


def _normalise(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return re.sub(r"\s+", " ", str(value).strip().lower()).strip(" .;:!?")


def _field_claim_mismatch(text: str, field: str, actual: Any) -> str | None:
    lower = text.lower()
    aliases = FIELD_ALIASES.get(field, ())
    if not aliases or not any(alias in lower for alias in aliases):
        return None
    expected = _normalise(actual)
    if expected in lower:
        return None
    alternatives = ENUM_ALTERNATIVES.get(field, ())
    stated = [value for value in alternatives if value in lower and value != expected]
    if stated:
        return (
            f"The response states {field} as {stated[0]!r}, "
            f"but the evidence records {expected!r}."
        )
    if isinstance(actual, (int, float)) and not isinstance(actual, bool):
        numbers = re.findall(r"\b\d+(?:\.\d+)?\b", lower)
        if numbers and expected not in numbers:
            return (
                f"The response value for {field} does not match "
                f"the recorded value {expected}."
            )
    return None


def check_schema(case: CyberBenchCase) -> list[CheckResult]:
    pack = case.agent_input.evidence_pack
    available_fields = {
        field
        for item in pack.evidence_items
        if item.source_type != "unverified_claim"
        for field in item.fields
    }
    missing = sorted(
        set(pack.evaluation_context.required_fields) - available_fields
    )
    return [
        CheckResult(
            check_name="required_fields",
            passed=not missing,
            severity="retry" if missing else "info",
            reason=(
                "All required evidence fields are available."
                if not missing
                else f"Missing required evidence fields: {', '.join(missing)}."
            ),
            evidence_ids=[item.evidence_id for item in pack.evidence_items],
        )
    ]


def check_provenance(case: CyberBenchCase) -> list[CheckResult]:
    items = case.agent_input.evidence_pack.evidence_items
    ids = [item.evidence_id for item in items]
    invalid = [
        item.evidence_id
        for item in items
        if (
            not item.source_record_id
            or not item.source_urls
            or item.source_type == "unverified_claim"
        )
    ]
    duplicate = len(ids) != len(set(ids))
    passed = bool(items) and not invalid and not duplicate
    reasons: list[str] = []
    if not items:
        reasons.append("No evidence items were supplied")
    if invalid:
        reasons.append(f"Invalid provenance: {', '.join(invalid)}")
    if duplicate:
        reasons.append("Evidence identifiers are duplicated")
    return [
        CheckResult(
            check_name="provenance",
            passed=passed,
            severity="reject" if not passed else "info",
            reason="Evidence provenance is valid." if passed else "; ".join(reasons) + ".",
            evidence_ids=ids,
        )
    ]


def check_freshness(case: CyberBenchCase) -> list[CheckResult]:
    pack = case.agent_input.evidence_pack
    evaluation_time = pack.evaluation_context.evaluation_time
    completed_at = pack.tool_record.completed_at
    if evaluation_time.tzinfo is None:
        evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)
    if completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)
    age_hours = (evaluation_time - completed_at).total_seconds() / 3600
    maximum = pack.evaluation_context.maximum_evidence_age_hours
    passed = 0 <= age_hours <= maximum
    return [
        CheckResult(
            check_name="freshness",
            passed=passed,
            severity="retry" if not passed else "info",
            reason=(
                f"Evidence age {age_hours:.1f} hours is within the {maximum}-hour limit."
                if passed
                else f"Evidence age {age_hours:.1f} hours exceeds the {maximum}-hour limit."
            ),
            evidence_ids=[item.evidence_id for item in pack.evidence_items],
        )
    ]


def check_tool_execution(case: CyberBenchCase) -> list[CheckResult]:
    tool = case.agent_input.evidence_pack.tool_record
    retryable = tool.recorded_status in {"timeout", "unavailable"} or tool.reported_status in {
        "timeout",
        "unavailable",
    }
    status_match = tool.recorded_status == tool.reported_status
    hash_match = tool.recorded_output_hash == tool.reported_output_hash
    succeeded = tool.recorded_status == "success"
    passed = succeeded and status_match and hash_match
    severity = "info" if passed else ("retry" if retryable else "reject")
    return [
        CheckResult(
            check_name="tool_execution",
            passed=passed,
            severity=severity,
            reason=(
                "Recorded and reported tool execution agree."
                if passed
                else (
                    "The tool result is temporarily unavailable."
                    if retryable
                    else "The reported tool execution contradicts the recorded execution."
                )
            ),
        )
    ]


def check_policy(case: CyberBenchCase) -> list[CheckResult]:
    action = extract_action(case.agent_input.candidate_response)
    policy = case.agent_input.evidence_pack.policy
    if not action:
        return [
            CheckResult(
                check_name="policy",
                passed=False,
                severity="human_review",
                reason="No recommended action was found for policy evaluation.",
            )
        ]
    normalised = _normalise(action)
    prohibited = {_normalise(item) for item in policy.prohibited_actions}
    approval = {_normalise(item) for item in policy.actions_requiring_approval}
    allowed = {_normalise(item) for item in policy.allowed_actions}
    memberships = [
        name
        for name, values in (
            ("allowed", allowed),
            ("approval-required", approval),
            ("prohibited", prohibited),
        )
        if normalised in values
    ]
    if len(memberships) > 1:
        passed, severity, reason = (
            False,
            "human_review",
            "The supplied policy classifies the recommended action "
            f"in conflicting categories ({', '.join(memberships)}): {action}.",
        )
    elif normalised in prohibited:
        passed, severity, reason = (
            False,
            "reject",
            f"The recommended action is prohibited by policy: {action}.",
        )
    elif normalised in approval:
        passed, severity, reason = (
            False,
            "human_review",
            f"The recommended action requires analyst approval: {action}.",
        )
    elif normalised in allowed:
        passed, severity, reason = (
            True,
            "info",
            f"The recommended action is allowed by policy: {action}.",
        )
    else:
        passed, severity, reason = (
            False,
            "human_review",
            f"The recommended action is not classified by the supplied policy: {action}.",
        )
    return [
        CheckResult(
            check_name="policy",
            passed=passed,
            severity=severity,
            reason=reason,
        )
    ]


def check_claim_values(case: CyberBenchCase, claims: list[Claim]) -> list[CheckResult]:
    observation = next((claim for claim in claims if claim.kind == "observation"), None)
    if observation is None:
        return [
            CheckResult(
                check_name="claim_values",
                passed=False,
                severity="reject",
                reason="No evidence-linked observation was produced.",
            )
        ]
    mismatches: list[str] = []
    conflicting_fields = {
        field for field, _, _ in _evidence_conflicts(case)
    }
    for item in case.agent_input.evidence_pack.evidence_items:
        if item.source_type == "unverified_claim":
            continue
        for field, value in item.fields.items():
            if field in conflicting_fields:
                continue
            mismatch = _field_claim_mismatch(observation.text, field, value)
            if mismatch:
                mismatches.append(mismatch)
    return [
        CheckResult(
            check_name="claim_values",
            passed=not mismatches,
            severity="reject" if mismatches else "info",
            reason=(
                "Material values in the response match the supplied evidence."
                if not mismatches
                else " ".join(mismatches)
            ),
            evidence_ids=observation.evidence_ids,
        )
    ]


def _evidence_conflicts(
    case: CyberBenchCase,
) -> list[tuple[str, str, str]]:
    items = [
        item
        for item in case.agent_input.evidence_pack.evidence_items
        if item.source_type != "unverified_claim"
    ]
    conflicts: list[tuple[str, str, str]] = []
    for left_index, left in enumerate(items):
        for right in items[left_index + 1 :]:
            for field in set(left.fields) & set(right.fields):
                if _normalise(left.fields[field]) != _normalise(right.fields[field]):
                    conflicts.append((field, left.evidence_id, right.evidence_id))
    return conflicts


def check_evidence_conflict(case: CyberBenchCase) -> list[CheckResult]:
    conflicts = _evidence_conflicts(case)
    reasons = [
        f"{field} differs between {left_id} and {right_id}"
        for field, left_id, right_id in conflicts
    ]
    items = [
        item
        for item in case.agent_input.evidence_pack.evidence_items
        if item.source_type != "unverified_claim"
    ]
    return [
        CheckResult(
            check_name="evidence_conflict",
            passed=not conflicts,
            severity="human_review" if conflicts else "info",
            reason=(
                "No conflicts were found between evidence items."
                if not conflicts
                else "; ".join(reasons) + "."
            ),
            evidence_ids=[item.evidence_id for item in items],
        )
    ]


def run_deterministic_checks(
    case: CyberBenchCase, claims: list[Claim]
) -> list[CheckResult]:
    return [
        *check_schema(case),
        *check_provenance(case),
        *check_freshness(case),
        *check_tool_execution(case),
        *check_policy(case),
        *check_claim_values(case, claims),
        *check_evidence_conflict(case),
    ]


def baseline_route(case: CyberBenchCase) -> RoutingDecision:
    """Baseline disposition using policy and stated confidence, without process checks."""
    policy_result = check_policy(case)[0]
    if not policy_result.passed:
        if policy_result.severity == "reject":
            return RoutingDecision(route=Route.REJECT, reason=policy_result.reason)
        return RoutingDecision(route=Route.HUMAN_REVIEW, reason=policy_result.reason)
    if case.agent_input.candidate_confidence < 0.5:
        return RoutingDecision(
            route=Route.RETRY,
            reason="Candidate confidence is below the baseline threshold.",
        )
    return RoutingDecision(
        route=Route.ACCEPT,
        reason="The unverified condition accepted the candidate recommendation.",
    )


def rule_based_judgements(
    claims: list[Claim], checks: list[CheckResult]
) -> list[ClaimJudgement]:
    claim_check = next(check for check in checks if check.check_name == "claim_values")
    observation = next(claim for claim in claims if claim.kind == "observation")
    return [
        ClaimJudgement(
            claim_id=observation.claim_id,
            classification="supported" if claim_check.passed else "contradicted",
            reason=claim_check.reason,
            evidence_ids=observation.evidence_ids,
        )
    ]


def route_from_checks(checks: list[CheckResult]) -> RoutingDecision:
    def reasons(results: list[CheckResult]) -> str:
        return " ".join(dict.fromkeys(check.reason for check in results))

    failed = [check for check in checks if not check.passed]
    rejects = [check for check in failed if check.severity == "reject"]
    if rejects:
        return RoutingDecision(
            route=Route.REJECT,
            reason=reasons(rejects),
        )
    reviews = [check for check in failed if check.severity == "human_review"]
    if reviews:
        return RoutingDecision(
            route=Route.HUMAN_REVIEW,
            reason=reasons(reviews),
        )
    retries = [check for check in failed if check.severity == "retry"]
    if retries:
        return RoutingDecision(
            route=Route.RETRY,
            reason=reasons(retries),
            retry_instructions=list(
                dict.fromkeys(check.reason for check in retries)
            ),
        )
    return RoutingDecision(
        route=Route.ACCEPT,
        reason="All required evidence, execution, claim and policy checks passed.",
    )


def has_competing_failure_routes(checks: list[CheckResult]) -> bool:
    severities = {
        check.severity
        for check in checks
        if not check.passed and check.severity != "info"
    }
    return len(severities) > 1
