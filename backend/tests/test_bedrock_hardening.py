import asyncio
import json
from unittest.mock import MagicMock
import pytest
import botocore.exceptions

from app.models.triage import DecisionEngineType, ModelInvocationStatus, TriagePriority
from app.services.decision_engine import (
    DecisionEngine,
    classify_bedrock_error,
    diagnose_bedrock_error,
    BedrockFailureCategory,
    BedrockTruncatedOutputError,
)
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


# ------------------------------------------------------------------------------
# Regression Suite: Bedrock Truncation & Malformed Output Handling
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bedrock_complete_valid_json_success():
    """1. Complete valid JSON response returns dual-ai mode with accurate model status."""
    decider = create_mock_decider_client(priority=TriagePriority.HIGH, confidence=0.89)
    mock_bedrock = MagicMock()
    valid_payload = {
        "priority": "High",
        "rationale": "Kernel vulnerability allows unauthorized local privilege escalation.",
        "risk_factors": ["Local execution vector", "Elevated CVSS 7.8"],
        "recommended_action": "Apply vendor security advisory update immediately.",
        "evidence_limitations": [],
    }
    mock_bedrock.converse.return_value = {
        "stopReason": "end_turn",
        "usage": {"inputTokens": 450, "outputTokens": 180, "totalTokens": 630},
        "output": {"message": {"content": [{"text": json.dumps(valid_payload)}]}},
    }

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="au.anthropic.claude-sonnet-4-6",
        allow_fallback=True,
    )
    resp = create_sample_response(cve_id="CVE-2023-38606", cvss_score=7.8)
    decision = await engine.evaluate_vulnerability(resp)

    assert decision.engine == DecisionEngineType.DUAL_AI
    assert decision.priority == TriagePriority.HIGH
    assert decision.decider_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_model_id == "au.anthropic.claude-sonnet-4-6"
    assert "Kernel vulnerability" in decision.rationale
    assert mock_bedrock.converse.call_count == 1


@pytest.mark.asyncio
async def test_bedrock_truncated_stop_reason_classification():
    """2. Response truncated with stopReason='max_tokens' raises BedrockTruncatedOutputError
    and is classified as OUTPUT_TRUNCATED rather than generic MALFORMED_OUTPUT."""
    err = BedrockTruncatedOutputError(
        "Bedrock output truncated before JSON completion (stopReason='max_tokens', outputTokens=1024).",
        stop_reason="max_tokens",
        output_tokens=1024,
    )
    category, code, retryable = classify_bedrock_error(err)

    assert category == BedrockFailureCategory.OUTPUT_TRUNCATED
    assert code == "MaxTokensReached"
    assert retryable is True


@pytest.mark.asyncio
async def test_bedrock_invalid_json_non_token_stop_reason():
    """3. Invalid JSON with non-token stop reason (e.g. end_turn) is classified as MALFORMED_OUTPUT."""
    err = json.JSONDecodeError("Unterminated string starting at line 1", "doc", 15)
    category, code, retryable = classify_bedrock_error(err)

    assert category == BedrockFailureCategory.MALFORMED_OUTPUT
    assert code == "JSONDecodeError"
    assert retryable is True

    val_err = ValueError("Bedrock output did not contain a valid JSON object")
    category2, code2, retryable2 = classify_bedrock_error(val_err)
    assert category2 == BedrockFailureCategory.MALFORMED_OUTPUT
    assert code2 == "ValueError"
    assert retryable2 is True


@pytest.mark.asyncio
async def test_bedrock_recovery_success_after_truncation(monkeypatch):
    """4. Recovery success: Attempt 1 is truncated (stopReason='max_tokens').
    Engine expands token budget and appends brevity guidance. Attempt 2 succeeds."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 2)
    monkeypatch.setattr("app.config.settings.retry_backoff_factor", 1.0)

    decider = create_mock_decider_client(priority=TriagePriority.MEDIUM, confidence=0.82)
    mock_bedrock = MagicMock()

    # Attempt 1: Truncated mid-rationale like in production
    truncated_text = '{"priority":"Medium","rationale":"CVE-2023-38606 is a kernel state modification vulnerability ... requiring local access and user interaction,'
    attempt1_resp = {
        "stopReason": "max_tokens",
        "usage": {"inputTokens": 500, "outputTokens": 1024, "totalTokens": 1524},
        "output": {"message": {"content": [{"text": truncated_text}]}},
    }

    # Attempt 2: Valid concise JSON
    success_payload = {
        "priority": "Medium",
        "rationale": "CVE-2023-38606 is a kernel state modification flaw requiring local access.",
        "risk_factors": ["Local access required", "User interaction required"],
        "recommended_action": "Apply iOS/macOS security updates.",
        "evidence_limitations": [],
    }
    attempt2_resp = {
        "stopReason": "end_turn",
        "usage": {"inputTokens": 520, "outputTokens": 140, "totalTokens": 660},
        "output": {"message": {"content": [{"text": json.dumps(success_payload)}]}},
    }

    mock_bedrock.converse.side_effect = [attempt1_resp, attempt2_resp]

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="au.anthropic.claude-sonnet-4-6",
        allow_fallback=True,
        max_tokens=1024,
    )
    resp = create_sample_response(cve_id="CVE-2023-38606", cvss_score=5.5)
    decision = await engine.evaluate_vulnerability(resp)

    assert mock_bedrock.converse.call_count == 2
    # Verify attempt 1 had maxTokens=1024 and attempt 2 had expanded maxTokens=2048
    call1_config = mock_bedrock.converse.call_args_list[0].kwargs["inferenceConfig"]
    call2_config = mock_bedrock.converse.call_args_list[1].kwargs["inferenceConfig"]
    assert call1_config["maxTokens"] == 1024
    assert call2_config["maxTokens"] == 2048

    # Verify attempt 2 prompt included brevity guidance
    call2_prompt = mock_bedrock.converse.call_args_list[1].kwargs["messages"][0]["content"][0]["text"]
    assert "Previous response exceeded token budget and was truncated" in call2_prompt

    assert decision.engine == DecisionEngineType.DUAL_AI
    assert decision.priority == TriagePriority.MEDIUM
    assert decision.decider_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_status == ModelInvocationStatus.SUCCESS


@pytest.mark.asyncio
async def test_bedrock_recovery_failure_returns_decider_only(monkeypatch):
    """5. Recovery failure: Both attempt 1 and attempt 2 truncate.
    Engine bounds retries (does NOT loop blindly 3 times) and degrades truthfully to decider-only."""
    monkeypatch.setattr("app.config.settings.max_decision_retries", 3)
    monkeypatch.setattr("app.config.settings.retry_backoff_factor", 1.0)

    decider = create_mock_decider_client(priority=TriagePriority.MEDIUM, confidence=0.85)
    mock_bedrock = MagicMock()

    truncated_resp = {
        "stopReason": "max_tokens",
        "usage": {"inputTokens": 500, "outputTokens": 1024, "totalTokens": 1524},
        "output": {"message": {"content": [{"text": '{"priority":"Medium","rationale":"CVE-2023-38606 truncated'}]}},
    }
    mock_bedrock.converse.return_value = truncated_resp

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="au.anthropic.claude-sonnet-4-6",
        allow_fallback=True,
    )
    resp = create_sample_response(cve_id="CVE-2023-38606", cvss_score=5.5)
    decision = await engine.evaluate_vulnerability(resp)

    # Max 1 retry for truncation -> exactly 2 calls, NOT 4 calls!
    assert mock_bedrock.converse.call_count == 2
    assert decision.engine == DecisionEngineType.DECIDER_ONLY
    assert decision.decider_status == ModelInvocationStatus.SUCCESS
    assert decision.bedrock_status == ModelInvocationStatus.FAILED
    assert decision.priority == TriagePriority.MEDIUM
    assert "output truncated" in decision.fallback_reason.lower() or "maxtokensreached" in decision.fallback_reason.lower()


def test_bedrock_diagnostics_without_secret_leakage():
    """6. Diagnostics capture model ID, stopReason, token usage, while scrubbing secrets."""
    err = BedrockTruncatedOutputError(
        "Truncation occurred with key=AKIAIOSFODNN7EXAMPLE",
        stop_reason="max_tokens",
        output_tokens=2048,
    )
    diag = diagnose_bedrock_error(err, model_id="au.anthropic.claude-sonnet-4-6", region_name="ap-southeast-2")

    assert "au.anthropic.claude-sonnet-4-6" in diag
    assert "max_tokens" in diag
    assert "2048 output tokens" in diag
    assert "ap-southeast-2" in diag
    # Ensure any secret pattern is scrubbed if present in error message
    assert "AKIAIOSFODNN7EXAMPLE" not in diag


@pytest.mark.asyncio
async def test_bedrock_cannot_override_stage1_priority():
    """7. Ensuring Bedrock cannot override Stage 1 priority.
    Stage 1 Strands Decider evaluated priority as Critical. Bedrock proposes Low.
    Final decision strictly preserves Stage 1 Critical priority."""
    decider = create_mock_decider_client(priority=TriagePriority.CRITICAL, confidence=0.96)
    mock_bedrock = MagicMock()

    # Bedrock attempts to contradict Stage 1 with "Low"
    contradicting_payload = {
        "priority": "Low",
        "rationale": "Model attempted to downgrade priority contrary to Stage 1 decision.",
        "risk_factors": ["Local component only"],
        "recommended_action": "Monitor routine advisory.",
        "evidence_limitations": [],
    }
    mock_bedrock.converse.return_value = {
        "stopReason": "end_turn",
        "usage": {"inputTokens": 300, "outputTokens": 100, "totalTokens": 400},
        "output": {"message": {"content": [{"text": json.dumps(contradicting_payload)}]}},
    }

    engine = DecisionEngine(
        bedrock_client=mock_bedrock,
        strands_client_instance=decider,
        model_id="au.anthropic.claude-sonnet-4-6",
        allow_fallback=True,
    )
    resp = create_sample_response(cvss_score=9.8, is_cisa_kev=True)
    decision = await engine.evaluate_vulnerability(resp)

    # Invariant: Operational priority authority belongs to Stage 1
    assert decision.priority == TriagePriority.CRITICAL
    assert decision.risk_validation.model_priority == TriagePriority.CRITICAL
