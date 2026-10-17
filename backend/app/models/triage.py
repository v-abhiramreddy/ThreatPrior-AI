from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

from app.models.enums import OverallStatus
from app.models.schemas import NormalizedVulnerability, Provenance


class TriagePriority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class DecisionEngineType(str, Enum):
    DUAL_AI = "dual-ai"
    DECIDER_ONLY = "decider-only"
    BEDROCK_ONLY = "bedrock-only"
    BASELINE = "baseline"
    UNAVAILABLE = "unavailable"
    # Legacy alias for backward compatibility
    AI = "dual-ai"


class ModelInvocationStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    NOT_INVOKED = "not_invoked"


class RiskValidationStatus(str, Enum):
    ALIGNED = "aligned"
    DISAGREEMENT = "disagreement"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class RiskValidationResult(BaseModel):
    """Transparent evidence-based policy validation of the AI triage decision.

    Compares the model's priority with deterministic, configurable evidence policy rules.
    Never overwrites the model's priority.
    """

    model_priority: TriagePriority = Field(
        ...,
        description="Original priority assigned by the AI decider or heuristic engine",
    )
    evidence_priority: Optional[TriagePriority] = Field(
        default=None,
        description="Deterministic evidence-based policy priority, or None if evidence is insufficient",
    )
    risk_validation_status: RiskValidationStatus = Field(
        ...,
        description="Validation outcome: 'aligned', 'disagreement', or 'insufficient_evidence'",
    )
    risk_factors: List[str] = Field(
        default_factory=list,
        description="Factual, auditable findings grounded strictly in available evidence",
    )
    validation_rules_version: str = Field(
        default="2026.1-policy",
        description="Identifier of the deterministic policy ruleset applied",
    )
    validation_explanation: str = Field(
        ...,
        description="Clear, transparent explanation of policy assessment and any discrepancies with model output",
    )


class Stage2BedrockOutput(BaseModel):
    """Strict schema for Amazon Bedrock Stage 2 structured JSON output."""

    priority: Optional[TriagePriority] = Field(
        default=None,
        description="Stage 2 output priority (must match Stage 1 Decider priority)",
    )
    rationale: str = Field(
        ...,
        min_length=1,
        description="Concise rationale strictly grounded in supplied evidence telemetry",
    )
    risk_factors: List[str] = Field(
        default_factory=list,
        description="Specific evidence-based risk factors identified during evaluation",
    )
    recommended_action: str = Field(
        ...,
        min_length=1,
        description="Specific, actionable next operational recommendation",
    )
    evidence_limitations: List[str] = Field(
        default_factory=list,
        description="Explicitly identified evidence gaps or telemetry limitations",
    )

    @field_validator("rationale", "recommended_action")
    @classmethod
    def validate_non_empty_str(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("String value cannot be empty or whitespace only.")
        return stripped


class TriageDecision(BaseModel):
    """Structured decision output produced by the genuine dual-model AI or deterministic baseline decision engine."""

    priority: TriagePriority = Field(
        ...,
        description="Assigned triage priority level: Critical, High, Medium, or Low",
    )
    rationale: str = Field(
        ...,
        description="Concise rationale strictly grounded in supplied evidence telemetry",
    )
    risk_factors: List[str] = Field(
        default_factory=list,
        description="Specific evidence-based risk factors identified during evaluation",
    )
    recommended_action: str = Field(
        ...,
        description="Specific, actionable next operational recommendation (decision-support only)",
    )
    recommendation_source: str = Field(
        default="general_policy_guidance",
        description="Attributable origin of the recommendation: 'cisa_kev_directive', 'bedrock_synthesis', or 'general_policy_guidance'",
    )
    recommendation_url: Optional[str] = Field(
        default=None,
        description="Authoritative reference URL if present in source evidence",
    )
    recommendation_is_verified: bool = Field(
        default=False,
        description="Whether the recommendation originates directly from an authoritative verified source (e.g. CISA BOD directive)",
    )
    authoritative_directive: Optional[str] = Field(
        default=None,
        description="Exact authoritative remediation directive from official sources (e.g. CISA BOD directive in KEV), retained separately from AI synthesis",
    )
    authoritative_directive_source: Optional[str] = Field(
        default=None,
        description="Attributable origin of the authoritative directive (e.g. 'cisa_kev')",
    )
    authoritative_directive_url: Optional[str] = Field(
        default=None,
        description="Reference URL for the authoritative directive if available in evidence",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model-derived distribution concentration score or heuristic rating (0.0 to 1.0)",
    )
    confidence_is_calibrated: bool = Field(
        default=False,
        description="False unless demonstrated by an actual empirical calibration evaluation (raw model concentration is uncalibrated)",
    )
    confidence_explanation: str = Field(
        ...,
        description="Clear explanation of decision certainty, uncertainties, or telemetry gaps",
    )
    evidence_limitations: List[str] = Field(
        default_factory=list,
        description="Explicitly identified evidence gaps, unavailable upstream sources, or dated metrics",
    )
    engine: DecisionEngineType = Field(
        ...,
        description="Actual engine utilized: 'dual-ai', 'decider-only', 'bedrock-only', 'baseline', or 'unavailable'",
    )
    # Distinct model provenance fields (Step 4)
    decider_model_id: Optional[str] = Field(
        default=None,
        description="Identifier of genuine Strands Decider 2B checkpoint actually invoked, or None if skipped/unavailable",
    )
    bedrock_model_id: Optional[str] = Field(
        default=None,
        description="Identifier of Amazon Bedrock model actually invoked, or None if skipped/unavailable",
    )
    decider_status: ModelInvocationStatus = Field(
        default=ModelInvocationStatus.NOT_INVOKED,
        description="Execution status of Strands Decider 2B invocation",
    )
    bedrock_status: ModelInvocationStatus = Field(
        default=ModelInvocationStatus.NOT_INVOKED,
        description="Execution status of Amazon Bedrock invocation",
    )
    model_id: Optional[str] = Field(
        default=None,
        description="Legacy backward-compatible identifier field; specific to engine mode",
    )
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the decision was finalized",
    )
    fallback_reason: Optional[str] = Field(
        default=None,
        description="If engine is 'baseline' or degraded, explanation of why AI model was bypassed or failed",
    )
    risk_validation: Optional[RiskValidationResult] = Field(
        default=None,
        description="Transparent evidence-based risk validation comparing model decision with deterministic policy",
    )


class TriageResponse(BaseModel):
    """Complete response payload for the vulnerability triage endpoint."""

    cve_id: str = Field(..., description="Common Vulnerabilities and Exposures Identifier")
    status: OverallStatus = Field(..., description="Overall aggregation status of evidence")
    retrieved_at: datetime = Field(..., description="UTC timestamp of evidence synthesis")
    decision: TriageDecision = Field(..., description="Structured triage decision")
    risk_validation: Optional[RiskValidationResult] = Field(
        default=None,
        description="Direct reference to decision risk validation result",
    )
    normalized: Optional[NormalizedVulnerability] = None
    provenance: Provenance = Field(..., description="Full source provenance and retrieval metadata")
    errors: List[str] = Field(default_factory=list, description="Any upstream warnings or errors")
