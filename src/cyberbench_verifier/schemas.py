from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Route(StrEnum):
    ACCEPT = "Accept"
    RETRY = "Retry"
    REJECT = "Reject"
    HUMAN_REVIEW = "Human Review"


class Condition(StrEnum):
    SINGLE_AGENT = "B1"
    MAS_UNVERIFIED = "B2"
    POST_HOC_JUDGE = "B3"
    SELECTIVE_VERIFIER = "P"


class EvidenceItem(BaseModel):
    evidence_id: str
    fields: dict[str, Any]
    source_record_id: str
    source_type: str
    source_urls: list[str]


class EvaluationContext(BaseModel):
    evaluation_time: datetime
    maximum_evidence_age_hours: int = Field(ge=0)
    required_fields: list[str]


class Policy(BaseModel):
    actions_requiring_approval: list[str]
    allowed_actions: list[str]
    prohibited_actions: list[str]


class ToolRecord(BaseModel):
    completed_at: datetime
    execution_id: str
    recorded_output_hash: str | None
    recorded_status: str
    reported_output_hash: str | None
    reported_status: str
    tool_name: str


class EvidencePack(BaseModel):
    schema_version: str
    evidence_pack_id: str
    evaluation_context: EvaluationContext
    evidence_items: list[EvidenceItem]
    policy: Policy
    tool_record: ToolRecord


class AgentInput(BaseModel):
    candidate_confidence: float = Field(ge=0, le=1)
    candidate_response: str
    domain: str
    evidence_pack: EvidencePack
    task_type: str
    tool_name: str
    user_query: str


class CyberBenchCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_input: AgentInput
    benchmark_version: str
    family_id: str
    scenario_id: str
    split: Literal["development", "validation", "test"]


class GoldLabel(BaseModel):
    scenario_id: str
    family_id: str
    split: str
    expected_route: Route
    expected_reason: str
    gold_defect_type: str
    gold_claim_support: str
    gold_tool_execution: str
    gold_provenance: str
    gold_policy_status: str
    gold_case_pattern: str
    annotation_status: str
    annotator_1_route: str = ""
    annotator_2_route: str = ""
    adjudicated_route: str = ""


class InvestigationPlan(BaseModel):
    steps: list[str]
    required_evidence_fields: list[str]


class Claim(BaseModel):
    claim_id: str
    text: str
    kind: Literal["observation", "inference", "recommendation", "uncertainty"]
    evidence_ids: list[str]


class CheckResult(BaseModel):
    check_name: str
    passed: bool
    severity: Literal["info", "retry", "reject", "human_review"]
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class ClaimJudgement(BaseModel):
    claim_id: str
    classification: Literal["supported", "contradicted", "insufficient", "unverifiable"]
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class RoutingDecision(BaseModel):
    route: Route
    reason: str
    retry_instructions: list[str] = Field(default_factory=list)


class Usage(BaseModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class RunTrace(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    scenario_id: str
    family_id: str
    split: str
    condition: Condition
    started_at: datetime
    completed_at: datetime
    latency_ms: float = Field(ge=0)
    usage: Usage = Field(default_factory=Usage)
    plan: InvestigationPlan
    evidence_ids: list[str]
    evidence_hashes: dict[str, str]
    claims: list[Claim]
    checks: list[CheckResult]
    judgements: list[ClaimJudgement]
    predicted_route: Route
    route_reason: str
    retry_used: bool = False
    retry_parent_run_id: str | None = None
    final_response: str

    @classmethod
    def started(
        cls,
        case: CyberBenchCase,
        condition: Condition,
    ) -> dict[str, Any]:
        return {
            "scenario_id": case.scenario_id,
            "family_id": case.family_id,
            "split": case.split,
            "condition": condition,
            "started_at": datetime.now(timezone.utc),
        }
