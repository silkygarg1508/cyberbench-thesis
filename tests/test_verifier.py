from cyberbench_verifier.schemas import Route
from cyberbench_verifier.verifier import (
    extract_action,
    extract_claims,
    route_from_checks,
    run_deterministic_checks,
)


def test_valid_case_is_accepted(sample_case) -> None:
    claims = extract_claims(sample_case)
    checks = run_deterministic_checks(sample_case, claims)
    assert all(check.passed for check in checks)
    assert route_from_checks(checks).route == Route.ACCEPT


def test_action_parser_accepts_supported_markers() -> None:
    assert extract_action("Finding. Recommendation: Retry collection.") == (
        "Retry collection"
    )
    assert extract_action(
        "Assessment: supported. Proposed next step: Isolate host."
    ) == "Isolate host"


def test_conflicting_policy_categories_require_review(sample_case) -> None:
    sample_case.agent_input.evidence_pack.policy.prohibited_actions.append(
        "Isolate host"
    )
    checks = run_deterministic_checks(sample_case, extract_claims(sample_case))
    assert route_from_checks(checks).route == Route.HUMAN_REVIEW


def test_recorded_execution_mismatch_is_rejected(sample_case) -> None:
    sample_case.agent_input.evidence_pack.tool_record.reported_status = "success"
    sample_case.agent_input.evidence_pack.tool_record.recorded_status = "failed"
    checks = run_deterministic_checks(sample_case, extract_claims(sample_case))
    assert route_from_checks(checks).route == Route.REJECT
