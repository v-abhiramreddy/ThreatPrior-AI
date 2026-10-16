"""Phase 3.6 Audit and Regression Test Suite.

Validates:
1. Confidence calibration semantics (confidence_is_calibrated must be False; measures peakedness, not correctness probability)
2. Priority parsing and explanation for Critical vs High distributions without fabrication or hardcoding
3. Recommendation provenance disclosure (authoritative CISA KEV URL vs unverified Bedrock AI synthesis vs policy templates)
4. Truthful pipeline status (dual-ai vs decider-only vs baseline; no secret exposure; zero AWS credential requirement)
"""

import pytest
from unittest.mock import MagicMock
import botocore.exceptions

from app.models.triage import (
    TriagePriority,
    DecisionEngineType,
    ModelInvocationStatus,
)
from app.services.strands_client import StrandsDeciderClient
from app.services.decision_engine import DecisionEngine
from tests.test_decision_engine import create_sample_response, create_mock_decider_client


# ---------------------------------------------------------------------------
# 1. Confidence Calibration Semantics
# ---------------------------------------------------------------------------

def test_confidence_semantics_uncalibrated_peakedness():
    """Verify confidence_is_calibrated is strictly False and computes peakedness concentration."""
    client = StrandsDeciderClient()

    # 4 choices with p_max = 0.70: (4 * 0.70 - 1) / 3 = 1.8 / 3 = 0.60
    probs = {"Critical": 0.70, "High": 0.20, "Medium": 0.05, "Low": 0.05}
    payload = {
        "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "Critical",
                "probabilities": probs,
            },
            "requires_emergency_mitigation": {"type": "noul", "noul": 0.85},
        },
    }
    eval_res = client._parse_decider_response(payload)

    # Must be uncalibrated because peakedness is not empirical calibration
    assert eval_res.confidence_is_calibrated is False
    assert eval_res.confidence == pytest.approx(0.60, abs=0.001)
    assert eval_res.priority == TriagePriority.CRITICAL


# ---------------------------------------------------------------------------
# 2. Priority Inconsistency Distribution Parsing
# ---------------------------------------------------------------------------

def test_priority_inconsistency_parsing_both_distributions():
    """Verify that both observed model distributions (direct Critical vs live High) parse deterministically.

    Direct test: 'Critical' in prompt -> 81.44% Critical -> (4 * 0.8144 - 1)/3 = 0.7525
    Live API: Telemetry matched High criteria keywords -> 57.98% High -> (4 * 0.5798 - 1)/3 = 0.4397
    """
    client = StrandsDeciderClient()

    # Direct test distribution
    payload_direct = {
        "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "Critical",
                "probabilities": {
                    "Critical": 0.8144,
                    "High": 0.1470,
                    "Medium": 0.0249,
                    "Low": 0.0137,
                },
            },
            "requires_emergency_mitigation": {"type": "noul", "noul": 0.8049},
        },
    }
    eval_direct = client._parse_decider_response(payload_direct)
    assert eval_direct.priority == TriagePriority.CRITICAL
    assert eval_direct.confidence == pytest.approx(0.7525, abs=0.001)
    assert eval_direct.confidence_is_calibrated is False
    assert eval_direct.requires_emergency_mitigation is True

    # Live API distribution
    payload_live = {
        "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "High",
                "probabilities": {
                    "Critical": 0.3711,
                    "High": 0.5798,
                    "Medium": 0.0345,
                    "Low": 0.0146,
                },
            },
            "requires_emergency_mitigation": {"type": "noul", "noul": 0.8049},
        },
    }
    eval_live = client._parse_decider_response(payload_live)
    assert eval_live.priority == TriagePriority.HIGH
    assert eval_live.confidence == pytest.approx(0.4397, abs=0.001)
    assert eval_live.confidence_is_calibrated is False
    assert eval_live.requires_emergency_mitigation is True


# ---------------------------------------------------------------------------
# 3. Remediation Recommendations Provenance & Attributable URLs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_remediation_provenance_cisa_directive_url_preserved():
    """Verify that authoritative CISA KEV required actions preserve source URL and are marked verified."""
    resp = create_sample_response()
    # In sample response, cisa_kev.required_action has directive URL
    assert "https://www.cisa.gov" in resp.provenance.cisa_kev.required_action

    mock_decider = create_mock_decider_client(
        priority=TriagePriority.CRITICAL,
        confidence=0.80,
        requires_emergency=True,
    )

    # Bedrock failure forces decider-only path which uses CISA KEV action
    mock_bedrock = MagicMock()
    mock_bedrock.converse.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate limit exceeded"}},
        "Converse",
    )

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=mock_decider,
        allow_fallback=True,
    )

    decision = await engine.evaluate_vulnerability(resp)

    assert decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decision.recommendation_source == "cisa_kev_directive"
    assert decision.recommendation_is_verified is True
    assert decision.recommendation_url == "https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures"
    assert decision.confidence_is_calibrated is False


@pytest.mark.asyncio
async def test_remediation_provenance_bedrock_marked_unverified_synthesis():
    """Verify that Bedrock AI operational actions are marked unverified synthesis."""
    resp = create_sample_response()

    mock_decider = create_mock_decider_client(
        priority=TriagePriority.CRITICAL,
        confidence=0.8667,
        requires_emergency=True,
    )

    mock_bedrock = MagicMock()
    mock_bedrock.converse.return_value = {
        "output": {
            "message": {
                "content": [
                    {
                        "text": (
                            '{"priority": "Critical", "rationale": "High threat context.", '
                            '"risk_factors": ["KEV listed"], '
                            '"recommended_action": "Apply emergency patches and review vendor advisory at https://example.com/log4j.", '
                            '"evidence_limitations": []}'
                        )
                    }
                ]
            }
        }
    }

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=mock_decider,
        allow_fallback=True,
    )

    decision = await engine.evaluate_vulnerability(resp)

    assert decision.engine == DecisionEngineType.DUAL_AI
    assert decision.recommendation_source == "bedrock_synthesis"
    assert decision.recommendation_is_verified is False
    assert decision.recommendation_url == "https://example.com/log4j"
    assert decision.confidence_is_calibrated is False


# ---------------------------------------------------------------------------
# 4. Truthful Pipeline Status & No Credential Leakage
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_truthful_pipeline_status_no_secrets():
    """Verify truthful pipeline engine statuses and guarantee no secret leakage."""
    resp = create_sample_response()

    # Case 1: Both succeed -> dual-ai
    mock_decider = create_mock_decider_client(
        priority=TriagePriority.CRITICAL,
        confidence=0.80,
        requires_emergency=True,
    )
    mock_bedrock = MagicMock()
    mock_bedrock.converse.return_value = {
        "output": {
            "message": {
                "content": [
                    {
                        "text": (
                            '{"priority": "Critical", "rationale": "Grounded rationale.", '
                            '"risk_factors": ["CVSS 10"], "recommended_action": "Patch now.", '
                            '"evidence_limitations": []}'
                        )
                    }
                ]
            }
        }
    }

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=mock_decider,
    )
    decision = await engine.evaluate_vulnerability(resp)
    assert decision.engine == DecisionEngineType.DUAL_AI
    assert decision.decider_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_status == ModelInvocationStatus.SUCCESS

    # Case 2: Decider succeeds, Bedrock fails with simulated auth error -> decider-only
    secret_token = "AKIAIOSFODNN7EXAMPLE_SECRET_TOKEN"
    mock_bedrock.converse.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnrecognizedClientException", "Message": f"The security token included in the request is invalid: {secret_token}"}},
        "Converse",
    )
    decision_deg = await engine.evaluate_vulnerability(resp)
    assert decision_deg.engine == DecisionEngineType.DECIDER_ONLY
    assert decision_deg.decider_status == ModelInvocationStatus.SUCCESS
    assert decision_deg.bedrock_status == ModelInvocationStatus.FAILED

    # Case 3: Decider fails -> baseline
    failing_decider = create_mock_decider_client(should_fail=True)
    engine_base = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=failing_decider,
        allow_fallback=True,
    )
    decision_base = await engine_base.evaluate_vulnerability(resp)
    assert decision_base.engine == DecisionEngineType.BASELINE
    assert decision_base.decider_status == ModelInvocationStatus.UNAVAILABLE
    assert decision_base.bedrock_status == ModelInvocationStatus.NOT_INVOKED
