from datetime import datetime, timezone

from cyberbench_verifier.schemas import (
    Condition,
    InvestigationPlan,
    Route,
    RunTrace,
)
from cyberbench_verifier.tracing import JsonlTraceStore


def test_trace_store_round_trip(tmp_path) -> None:
    trace = RunTrace(
        scenario_id="SAMPLE-001",
        family_id="family-example",
        split="development",
        condition=Condition.SELECTIVE_VERIFIER,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        latency_ms=1000,
        plan=InvestigationPlan(steps=["Verify evidence"], required_evidence_fields=[]),
        evidence_ids=[],
        evidence_hashes={},
        claims=[],
        checks=[],
        judgements=[],
        predicted_route=Route.HUMAN_REVIEW,
        route_reason="Example trace.",
        final_response="Human Review",
    )
    store = JsonlTraceStore(tmp_path / "traces.jsonl")
    store.append(trace)
    assert store.read_all() == [trace]
