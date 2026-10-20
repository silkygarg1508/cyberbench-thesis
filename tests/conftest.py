from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyberbench_verifier.schemas import (
    AgentInput,
    CyberBenchCase,
    EvaluationContext,
    EvidenceItem,
    EvidencePack,
    Policy,
    ToolRecord,
)


@pytest.fixture
def sample_case() -> CyberBenchCase:
    return CyberBenchCase(
        benchmark_version="1.0",
        family_id="family-example",
        scenario_id="SAMPLE-001",
        split="development",
        agent_input=AgentInput(
            candidate_confidence=0.9,
            candidate_response=(
                "Assessment: The endpoint alert has high severity. "
                "Recommended action: Isolate host."
            ),
            domain="endpoint",
            task_type="alert_triage",
            tool_name="endpoint_record",
            user_query="Review the endpoint alert.",
            evidence_pack=EvidencePack(
                schema_version="1.0",
                evidence_pack_id="EP-001",
                evaluation_context=EvaluationContext(
                    evaluation_time=datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
                    maximum_evidence_age_hours=24,
                    required_fields=["severity"],
                ),
                evidence_items=[
                    EvidenceItem(
                        evidence_id="E-001",
                        fields={"severity": "high"},
                        source_record_id="record-001",
                        source_type="tool_output",
                        source_urls=["https://example.invalid/evidence/record-001"],
                    )
                ],
                policy=Policy(
                    actions_requiring_approval=[],
                    allowed_actions=["Isolate host"],
                    prohibited_actions=[],
                ),
                tool_record=ToolRecord(
                    completed_at=datetime(2026, 1, 1, 11, tzinfo=timezone.utc),
                    execution_id="execution-001",
                    recorded_output_hash="hash-001",
                    recorded_status="success",
                    reported_output_hash="hash-001",
                    reported_status="success",
                    tool_name="endpoint_record",
                ),
            ),
        ),
    )
