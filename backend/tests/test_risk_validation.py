"""Regression Test Suite for Evidence-Based Risk Validation Layer (Phase 3.7).

Validates:
1. Log4Shell (CVSS 10.0, CISA KEV listed, high EPSS -> Critical policy)
2. Low CVSS (< 4.0), no KEV listing -> Low policy
3. Missing EPSS data (enforcing missing != zero risk)
4. Failed CISA KEV lookup (enforcing failed != NOT_LISTED -> insufficient_evidence)
5. Conflicting model and evidence assessments (status: disagreement)
6. Agreement between model and evidence assessments (status: aligned)
7. Proof that validation never overwrites original model priority
8. API response serialization of risk validation object
9. Decider-only, dual-ai, and baseline mode compatibility
"""

from datetime import datetime, timezone
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models.enums import OverallStatus, SeverityLevel, SourceStatus
from app.models.schemas import (
    CisaKevProvenance,
    EpssProvenance,
    NormalizedVulnerability,
    NvdProvenance,
    Provenance,
    VulnerabilityResponse,
)
from app.models.triage import (
    DecisionEngineType,
    ModelInvocationStatus,
    RiskValidationResult,
    RiskValidationStatus,
    TriageDecision,
    TriagePriority,
    TriageResponse,
)
from app.services.decision_engine import DecisionEngine
from app.services.risk_validator import EvidenceRiskValidator, risk_validator
from app.services.strands_client import DeciderEvaluation, StrandsDeciderClient


def _create_sample_response(
    cve_id: str = "CVE-2021-44228",
    cvss_score: float = 10.0,
    is_kev: bool = True,
    kev_status: SourceStatus = SourceStatus.AVAILABLE,
    epss_prob: float = 0.97,
    epss_status: SourceStatus = SourceStatus.AVAILABLE,
    nvd_status: SourceStatus = SourceStatus.AVAILABLE,
) -> VulnerabilityResponse:
    """Helper to synthesize a mocked VulnerabilityResponse with exact telemetry facts."""
    return VulnerabilityResponse(
        cve_id=cve_id,
        status=OverallStatus.OK,
        retrieved_at=datetime.now(timezone.utc),
        normalized=NormalizedVulnerability(
            title=f"Test Vulnerability {cve_id}",
            description="Remote code execution vulnerability.",
            primary_severity=SeverityLevel.CRITICAL if cvss_score >= 9.0 else SeverityLevel.HIGH if cvss_score >= 7.0 else SeverityLevel.LOW,
            cvss_score=cvss_score,
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            is_cisa_kev=is_kev,
            cisa_required_action="Apply patches immediately" if is_kev else None,
            epss_probability=epss_prob,
            epss_percentile=0.99 if epss_prob else None,
            affected_cpe_count=1,
        ),
        provenance=Provenance(
            nvd=NvdProvenance(
                source="https://services.nvd.nist.gov/rest/json/cves/2.0",
                status=nvd_status,
                published_date="2021-12-10T10:15:09.143",
                last_modified_date="2026-08-11T19:33:44.513",
                weaknesses=["CWE-502"],
                cpe_configurations=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
            ),
            cisa_kev=CisaKevProvenance(
                source="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                status=kev_status,
                catalog_version="2026.10.15",
                is_listed=is_kev,
                date_added="2021-12-10" if is_kev else None,
                vendor_project="Apache",
                product="Log4j",
                vulnerability_name="Log4Shell",
                required_action="Apply vendor mitigation or isolate.",
                notes="Target of Binding Directive 22-01.",
                error_message="Connection timed out to CISA" if kev_status == SourceStatus.TIMEOUT else None,
            ),
            epss=EpssProvenance(
                source="https://api.first.org/data/v1/epss",
                status=epss_status,
                probability=epss_prob,
                percentile=0.99 if epss_prob is not None else None,
                score_date="2026-10-15" if epss_prob is not None else None,
                interpretive_note="Top 1% exploit likelihood",
                error_message="EPSS API returned 503" if epss_status == SourceStatus.FAILED else None,
            ),
        ),
        errors=[],
    )


# ==============================================================================
# Test 1: Log4Shell (CVSS 10.0, CISA KEV listed, high EPSS)
# ==============================================================================
def test_1_log4shell_validation_critical():
    resp = _create_sample_response(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        is_kev=True,
        epss_prob=0.974,
    )
    result = risk_validator.validate(resp, model_priority=TriagePriority.CRITICAL)

    assert result.evidence_priority == TriagePriority.CRITICAL
    assert result.risk_validation_status == RiskValidationStatus.ALIGNED
    assert result.model_priority == TriagePriority.CRITICAL
    assert "2026.1-policy" in result.validation_rules_version

    # Ensure findings are grounded with dates and metrics
    findings_str = " ".join(result.risk_factors)
    assert "10.0" in findings_str
    assert "2021-12-10" in findings_str  # CISA KEV added date
    assert "2026-10-15" in findings_str  # EPSS score date
    assert "97.40%" in findings_str


# ==============================================================================
# Test 2: Low CVSS and no KEV listing
# ==============================================================================
def test_2_low_cvss_no_kev_listing():
    resp = _create_sample_response(
        cve_id="CVE-2024-0001",
        cvss_score=2.3,
        is_kev=False,
        kev_status=SourceStatus.NOT_LISTED,
        epss_prob=0.005,
    )
    result = risk_validator.validate(resp, model_priority=TriagePriority.LOW)

    assert result.evidence_priority == TriagePriority.LOW
    assert result.risk_validation_status == RiskValidationStatus.ALIGNED
    assert result.model_priority == TriagePriority.LOW
    findings_str = " ".join(result.risk_factors)
    assert "Absence from KEV catalog is not proof of safety" in findings_str
    assert "2.3" in findings_str


# ==============================================================================
# Test 3: Missing EPSS data (enforcing missing != zero risk)
# ==============================================================================
def test_3_missing_epss_data():
    resp = _create_sample_response(
        cve_id="CVE-2024-1111",
        cvss_score=7.8,
        is_kev=False,
        kev_status=SourceStatus.NOT_LISTED,
        epss_prob=None,
        epss_status=SourceStatus.NOT_FOUND,
    )
    result = risk_validator.validate(resp, model_priority=TriagePriority.HIGH)

    # Missing EPSS must not drop priority to Low; CVSS 7.8 evaluates to HIGH per policy
    assert result.evidence_priority == TriagePriority.HIGH
    assert result.risk_validation_status == RiskValidationStatus.ALIGNED
    findings_str = " ".join(result.risk_factors)
    assert "Policy rule enforces that missing or failed EPSS data is NOT interpreted as zero risk" in findings_str


# ==============================================================================
# Test 4: Failed CISA KEV lookup (must NOT be treated as NOT_LISTED)
# ==============================================================================
def test_4_failed_cisa_kev_lookup_yields_insufficient_evidence():
    resp = _create_sample_response(
        cve_id="CVE-2024-2222",
        cvss_score=8.0,
        is_kev=False,
        kev_status=SourceStatus.TIMEOUT,  # KEV failed!
        epss_prob=0.15,
    )
    result = risk_validator.validate(resp, model_priority=TriagePriority.HIGH)

    # Per policy requirement: failed KEV lookup is NOT treated as NOT_LISTED.
    # Results in insufficient_evidence rather than a false assertion of safety.
    assert result.risk_validation_status == RiskValidationStatus.INSUFFICIENT_EVIDENCE
    assert result.evidence_priority is None
    assert "failed lookups cannot be treated as NOT_LISTED" in result.validation_explanation
    findings_str = " ".join(result.risk_factors)
    assert "Warning: Query failure cannot be interpreted as NOT_LISTED" in findings_str


# ==============================================================================
# Test 5: Conflicting model and evidence assessments (disagreement)
# ==============================================================================
def test_5_conflicting_model_and_evidence_assessments():
    # Real-world Strands Decider case: Model picked 'High' based on prompt criteria keywords,
    # but evidence policy evaluates to 'Critical' because KEV is listed with CVSS 10.0 and high EPSS.
    resp = _create_sample_response(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        is_kev=True,
        epss_prob=0.97,
    )
    result = risk_validator.validate(resp, model_priority=TriagePriority.HIGH)

    assert result.risk_validation_status == RiskValidationStatus.DISAGREEMENT
    assert result.model_priority == TriagePriority.HIGH
    assert result.evidence_priority == TriagePriority.CRITICAL
    assert "Policy Disagreement: Model assigned 'High', while deterministic evidence policy evaluates to 'Critical'" in result.validation_explanation
    assert "Deterministic policy findings represent organizational rules, not an alternate AI model" in result.validation_explanation


# ==============================================================================
# Test 6: Agreement between model and evidence assessments (aligned)
# ==============================================================================
def test_6_agreement_between_model_and_evidence_assessments():
    resp = _create_sample_response(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        is_kev=True,
        epss_prob=0.97,
    )
    result = risk_validator.validate(resp, model_priority=TriagePriority.CRITICAL)

    assert result.risk_validation_status == RiskValidationStatus.ALIGNED
    assert result.model_priority == TriagePriority.CRITICAL
    assert result.evidence_priority == TriagePriority.CRITICAL
    assert "Policy Aligned: Model-assigned 'Critical' priority is fully consistent" in result.validation_explanation


# ==============================================================================
# Test 7: Proof validation never overwrites original model priority
# ==============================================================================
def test_7_proof_validation_never_overwrites_original_model_priority():
    resp = _create_sample_response(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        is_kev=True,
        epss_prob=0.97,
    )

    # Let's say model priority is LOW
    model_orig_priority = TriagePriority.LOW
    result = risk_validator.validate(resp, model_priority=model_orig_priority)

    # The original model priority remains LOW
    assert result.model_priority == TriagePriority.LOW
    assert model_orig_priority == TriagePriority.LOW
    # The policy evidence priority is CRITICAL
    assert result.evidence_priority == TriagePriority.CRITICAL
    # It must detect disagreement without altering model_priority
    assert result.risk_validation_status == RiskValidationStatus.DISAGREEMENT


# ==============================================================================
# Test 8: API serialization and schema validation of risk_validation
# ==============================================================================
def test_8_api_serialization_of_risk_validation():
    decision = TriageDecision(
        priority=TriagePriority.HIGH,
        rationale="Strands Decider 2B fast evaluation.",
        risk_factors=["Critical remote execution"],
        recommended_action="Apply security update.",
        confidence=0.88,
        confidence_is_calibrated=False,
        confidence_explanation="Normalized max-probability distribution concentration; uncalibrated.",
        evidence_limitations=[],
        engine=DecisionEngineType.DECIDER_ONLY,
        decider_model_id="StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        bedrock_model_id=None,
        decider_status=ModelInvocationStatus.SUCCESS,
        bedrock_status=ModelInvocationStatus.FAILED,
        decided_at=datetime.now(timezone.utc),
        risk_validation=RiskValidationResult(
            model_priority=TriagePriority.HIGH,
            evidence_priority=TriagePriority.CRITICAL,
            risk_validation_status=RiskValidationStatus.DISAGREEMENT,
            risk_factors=["CISA KEV confirmed active threat", "NVD CVSS Base Score: 10.0"],
            validation_rules_version="2026.1-policy",
            validation_explanation="Policy Disagreement: Model assigned 'High', policy evaluates to 'Critical'.",
        ),
    )

    resp = _create_sample_response()
    triage_response = TriageResponse(
        cve_id=resp.cve_id,
        status=resp.status,
        retrieved_at=resp.retrieved_at,
        decision=decision,
        risk_validation=decision.risk_validation,
        normalized=resp.normalized,
        provenance=resp.provenance,
        errors=[],
    )

    # Serialize to dict / json
    serialized = triage_response.model_dump(mode="json")

    assert "risk_validation" in serialized
    assert serialized["risk_validation"]["model_priority"] == "High"
    assert serialized["risk_validation"]["evidence_priority"] == "Critical"
    assert serialized["risk_validation"]["risk_validation_status"] == "disagreement"
    assert serialized["risk_validation"]["validation_rules_version"] == "2026.1-policy"
    assert len(serialized["risk_validation"]["risk_factors"]) == 2
    assert "Policy Disagreement" in serialized["risk_validation"]["validation_explanation"]
    assert serialized["decision"]["risk_validation"] is not None


# ==============================================================================
# Test 9: Existing decider-only and baseline modes retain risk validation
# ==============================================================================
@pytest.mark.asyncio
async def test_9_decider_only_and_baseline_modes_retain_risk_validation():
    engine = DecisionEngine(allow_fallback=True)
    resp = _create_sample_response(cvss_score=8.5, is_kev=True)

    # 1. Baseline mode
    baseline_decision = engine.evaluate_baseline(resp, fallback_reason="AI disabled")
    assert baseline_decision.engine == DecisionEngineType.BASELINE
    assert baseline_decision.risk_validation is not None
    assert baseline_decision.risk_validation.evidence_priority == TriagePriority.CRITICAL
    assert baseline_decision.risk_validation.validation_rules_version == "2026.1-policy"

    # 2. Decider-only mode
    mock_decider_eval = DeciderEvaluation(
        priority=TriagePriority.HIGH,
        priority_probabilities={"Critical": 0.2, "High": 0.75, "Medium": 0.05, "Low": 0.0},
        confidence=0.75,
        confidence_is_calibrated=False,
        emergency_mitigation_noul=0.85,
        requires_emergency_mitigation=True,
        model_id="StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        status=ModelInvocationStatus.SUCCESS,
    )
    decider_decision = engine._create_decider_only_decision(
        resp, mock_decider_eval, bedrock_error="Bedrock throttled"
    )
    assert decider_decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decider_decision.risk_validation is not None
    assert decider_decision.risk_validation.model_priority == TriagePriority.HIGH
    assert decider_decision.risk_validation.evidence_priority == TriagePriority.CRITICAL
    assert decider_decision.risk_validation.risk_validation_status == RiskValidationStatus.DISAGREEMENT
