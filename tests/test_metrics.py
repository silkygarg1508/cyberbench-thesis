from datetime import datetime, timezone

from cyberbench_verifier.metrics import evaluate_traces
from cyberbench_verifier.schemas import (
    Condition,
    GoldLabel,
    InvestigationPlan,
    Route,
    RunTrace,
)
from cyberbench_verifier.verifier import extract_claims, run_deterministic_checks


def test_metrics_for_known_case(sample_case) -> None:
    claims = extract_claims(sample_case)
    checks = run_deterministic_checks(sample_case, claims)
    trace = RunTrace(
        scenario_id=sample_case.scenario_id,
        family_id=sample_case.family_id,
        split=sample_case.split,
        condition=Condition.SELECTIVE_VERIFIER,
        started_at=datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 12, 0, 1, tzinfo=timezone.utc),
        latency_ms=1000,
        plan=InvestigationPlan(steps=["Verify evidence"], required_evidence_fields=["severity"]),
        evidence_ids=["E-001"],
        evidence_hashes={"E-001": "hash-001"},
        claims=claims,
        checks=checks,
        judgements=[],
        predicted_route=Route.ACCEPT,
        route_reason="All checks passed.",
        final_response="Accept",
    )
    label = GoldLabel(
        scenario_id=sample_case.scenario_id,
        family_id=sample_case.family_id,
        split=sample_case.split,
        expected_route=Route.ACCEPT,
        expected_reason="Evidence supports the route.",
        gold_defect_type="none",
        gold_claim_support="supported",
        gold_tool_execution="valid",
        gold_provenance="valid",
        gold_policy_status="allowed",
        gold_case_pattern="example",
        annotation_status="complete",
    )
    result = evaluate_traces([trace], {label.scenario_id: label})
    proposed = result["conditions"]["P"]
    assert proposed["routing_accuracy"] == 1.0
    assert proposed["macro_f1"] == 0.25
    assert proposed["false_acceptance_rate"] == 0.0
