import asyncio
import json
from unittest.mock import MagicMock
import pytest
import botocore.exceptions

from app.models.triage import DecisionEngineType, ModelInvocationStatus, TriagePriority
from app.services.decision_engine import DecisionEngine, classify_bedrock_error, BedrockFailureCategory
from tests.test_decision_engine import create_sample_response, create_mock_decider_client


@pytest.mark.asyncio
async def test_bedrock_transient_throttling_recovery(monkeypatch):
    """Verify that a transient throttling error on attempt 1 recovers on attempt 2 and returns dual-ai."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 2)
    monkeypatch.setattr("app.config.settings.retry_backoff_factor", 1.0)

    decider = create_mock_decider_client(priority=TriagePriority.HIGH, confidence=0.91)

    mock_bedrock = MagicMock()
    throttle_err = botocore.exceptions.ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate limit exceeded"}},
        "Converse",
    )
    success_payload = {
        "priority": "High",
        "rationale": "High severity flaw recovered after transient throttling.",
        "risk_factors": ["CVSS elevated"],
        "recommended_action": "Apply patch during regular maintenance window.",
        "evidence_limitations": [],
    }
    mock_bedrock.converse.side_effect = [
        throttle_err,
        {"output": {"message": {"content": [{"text": json.dumps(success_payload)}]}}},
    ]

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="amazon.nova-lite-v1:0",
        allow_fallback=True,
    )
    resp = create_sample_response(cvss_score=8.5)
    decision = await engine.evaluate_vulnerability(resp)

    assert decision.engine == DecisionEngineType.DUAL_AI
    assert decision.decider_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_status == ModelInvocationStatus.SUCCESS
    assert mock_bedrock.converse.call_count == 2


@pytest.mark.asyncio
async def test_bedrock_exhausted_retries_degrades_truthfully(monkeypatch):
    """Verify that when retryable errors exhaust all bounded retries, it truthfully returns decider-only."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 2)
    monkeypatch.setattr("app.config.settings.retry_backoff_factor", 1.0)

    decider = create_mock_decider_client(priority=TriagePriority.CRITICAL, confidence=0.95)

    mock_bedrock = MagicMock()
    server_err = botocore.exceptions.ClientError(
        {"Error": {"Code": "InternalServerException", "Message": "Bedrock internal service error"}},
        "Converse",
    )
    mock_bedrock.converse.side_effect = server_err

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="amazon.nova-lite-v1:0",
        allow_fallback=True,
    )
    resp = create_sample_response()
    decision = await engine.evaluate_vulnerability(resp)

    # 1 initial + 2 retries = 3 calls total
    assert mock_bedrock.converse.call_count == 3
    assert decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decision.decider_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_status == ModelInvocationStatus.FAILED
    assert "InternalServerException" in decision.fallback_reason


@pytest.mark.asyncio
async def test_bedrock_permanent_access_denied_never_retried(monkeypatch):
    """Verify permanent AccessDenied error is NOT retried and fails immediately on attempt 1."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 3)

    decider = create_mock_decider_client(priority=TriagePriority.CRITICAL, confidence=0.95)

    mock_bedrock = MagicMock()
    denied_err = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User not authorized"}},
        "Converse",
    )
    mock_bedrock.converse.side_effect = denied_err

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="au.anthropic.claude-sonnet-4-6",
        allow_fallback=True,
    )
    resp = create_sample_response()
    decision = await engine.evaluate_vulnerability(resp)

    # Must NOT retry: exactly 1 call
    assert mock_bedrock.converse.call_count == 1
    assert decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decision.bedrock_status == ModelInvocationStatus.FAILED
    assert "AccessDenied" in decision.fallback_reason


@pytest.mark.asyncio
async def test_bedrock_permanent_missing_credentials_never_retried(monkeypatch):
    """Verify permanent NoCredentialsError is NOT retried."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 3)

    decider = create_mock_decider_client(priority=TriagePriority.HIGH, confidence=0.88)

    mock_bedrock = MagicMock()
    mock_bedrock.converse.side_effect = botocore.exceptions.NoCredentialsError()

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="au.anthropic.claude-sonnet-4-6",
        allow_fallback=True,
    )
    resp = create_sample_response(cvss_score=7.5)
    decision = await engine.evaluate_vulnerability(resp)

    assert mock_bedrock.converse.call_count == 1
    assert decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decision.bedrock_status == ModelInvocationStatus.FAILED
    assert "No AWS credentials discovered" in decision.fallback_reason


@pytest.mark.asyncio
async def test_bedrock_timeout_retries_and_degrades(monkeypatch):
    """Verify asyncio.TimeoutError is retried boundedly and degrades safely."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 1)
    monkeypatch.setattr("app.config.settings.retry_backoff_factor", 1.0)
    monkeypatch.setattr("app.config.settings.decision_timeout_seconds", 0.05)

    decider = create_mock_decider_client(priority=TriagePriority.CRITICAL, confidence=0.95)

    mock_bedrock = MagicMock()
    # Bedrock call blocks longer than timeout
    import time
    def slow_call(*args, **kwargs):
        time.sleep(0.1)
        return {}

    mock_bedrock.converse.side_effect = slow_call

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="amazon.nova-lite-v1:0",
        allow_fallback=True,
    )
    resp = create_sample_response()
    decision = await engine.evaluate_vulnerability(resp)

    assert decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decision.bedrock_status == ModelInvocationStatus.FAILED
    assert "timed out" in decision.fallback_reason


@pytest.mark.asyncio
async def test_bedrock_concurrent_deduplication():
    """Verify concurrent requests for the exact same CVE await the single in-flight execution."""
    decider = create_mock_decider_client(priority=TriagePriority.CRITICAL, confidence=0.95)

    mock_bedrock = MagicMock()
    success_payload = {
        "priority": "Critical",
        "rationale": "High priority exploit confirmed.",
        "risk_factors": ["CVSS 10.0"],
        "recommended_action": "Apply immediate mitigation.",
        "evidence_limitations": [],
    }

    import time
    def delayed_converse(*args, **kwargs):
        time.sleep(0.05)
        return {"output": {"message": {"content": [{"text": json.dumps(success_payload)}]}}}

    mock_bedrock.converse.side_effect = delayed_converse

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="amazon.nova-lite-v1:0",
        allow_fallback=True,
    )
    resp1 = create_sample_response(cve_id="CVE-2021-44228")
    resp2 = create_sample_response(cve_id="CVE-2021-44228")

    # Launch two concurrent triage tasks for the same CVE
    d1, d2 = await asyncio.gather(
        engine.evaluate_vulnerability(resp1),
        engine.evaluate_vulnerability(resp2),
    )

    assert d1.priority == TriagePriority.CRITICAL
    assert d2.priority == TriagePriority.CRITICAL
    # Bedrock converse should be called only ONCE due to in-flight deduplication
    assert mock_bedrock.converse.call_count == 1
