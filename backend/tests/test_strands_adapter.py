import asyncio
import sys
import unittest.mock
from unittest.mock import MagicMock
import httpx
import pytest
import respx

from app.models.enums import OverallStatus, SeverityLevel, SourceStatus
from app.models.schemas import (
    CisaKevProvenance,
    CvssMetrics,
    EpssProvenance,
    NormalizedVulnerability,
    NvdProvenance,
    Provenance,
    VulnerabilityResponse,
)
from app.models.triage import ModelInvocationStatus, TriagePriority
from app.services.strands_client import (
    DeciderEvaluation,
    StrandsDeciderClient,
    StrandsDeciderError,
    StrandsDeciderTimeoutError,
    StrandsDeciderUnavailableError,
    StrandsDeciderValidationError,
    clear_local_engine_cache,
)


def create_sample_vuln(
    cve_id: str = "CVE-2021-44228",
    cvss_score: float = 10.0,
    is_cisa_kev: bool = True,
    epss_prob: float = 0.974,
) -> VulnerabilityResponse:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return VulnerabilityResponse(
        cve_id=cve_id,
        status=OverallStatus.OK,
        retrieved_at=now,
        normalized=NormalizedVulnerability(
            title="Apache Log4j2 RCE",
            description="Log4j2 JNDI RCE vulnerability in LDAP handling.",
            primary_severity=SeverityLevel.CRITICAL,
            cvss_score=cvss_score,
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            is_cisa_kev=is_cisa_kev,
            cisa_required_action="Apply emergency patch immediately.",
            cisa_due_date="2021-12-24",
            epss_probability=epss_prob,
            epss_percentile=0.998,
            affected_cpe_count=4,
        ),
        provenance=Provenance(
            nvd=NvdProvenance(
                source="NIST NVD API v2.0",
                retrieved_at=now,
                status=SourceStatus.AVAILABLE,
                cvss_v31=CvssMetrics(
                    base_score=cvss_score,
                    severity=SeverityLevel.CRITICAL,
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                ),
            ),
            cisa_kev=CisaKevProvenance(
                source="CISA KEV Catalog",
                retrieved_at=now,
                status=SourceStatus.LISTED if is_cisa_kev else SourceStatus.NOT_LISTED,
                is_listed=is_cisa_kev,
                date_added="2021-12-10",
                notes="Active exploitation observed.",
            ),
            epss=EpssProvenance(
                source="FIRST.org EPSS API v3",
                retrieved_at=now,
                status=SourceStatus.AVAILABLE,
                probability=epss_prob,
                percentile=0.998,
                score_date="2026-10-15",
                interpretive_note="30-day forecast.",
            ),
        ),
    )


# 1. State string format is concise and grounded in normalized telemetry
def test_format_evidence_state():
    client = StrandsDeciderClient()
    resp = create_sample_vuln()
    state = client.format_evidence_state(resp)

    assert "CVE-2021-44228" in state
    assert "CVSS Base Score: 10.0" in state
    assert "CISA KEV Listed: YES" in state
    assert "EPSS Exploitation Probability (30-day): 97.40%" in state


# 2. Remote HTTP server invocation (POST /v1/systemone) matches official schema
@pytest.mark.asyncio
async def test_remote_http_server_invocation():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url, mode="remote")
    resp = create_sample_vuln()

    mock_response_payload = {
        "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "Critical",
                "probabilities": {
                    "Critical": 0.95,
                    "High": 0.03,
                    "Medium": 0.01,
                    "Low": 0.01,
                },
                "confidence": 0.9333,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.98,
            },
        },
        "usage": {"input_tokens": 120, "output_tokens": 15},
    }

    async with respx.mock(assert_all_called=True) as respx_mock:
        route = respx_mock.post(f"{mock_server_url}/v1/systemone").respond(
            status_code=200,
            json=mock_response_payload,
        )

        evaluation = await client.evaluate(resp)

        assert route.called
        assert isinstance(evaluation, DeciderEvaluation)
        assert evaluation.priority == TriagePriority.CRITICAL
        assert evaluation.confidence == 0.9333
        assert evaluation.confidence_is_calibrated is False
        assert evaluation.requires_emergency_mitigation is True
        assert evaluation.emergency_mitigation_noul == 0.98
        assert evaluation.model_id == "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610"
        assert evaluation.status == ModelInvocationStatus.SUCCESS


# 3. Derive model confidence directly from probability distribution (uncalibrated peakedness)
def test_model_confidence_distribution_concentration_calculation():
    client = StrandsDeciderClient()
    # 4 choices: formula is (4 * p_max - 1) / 3
    probs = {"Critical": 0.94, "High": 0.04, "Medium": 0.01, "Low": 0.01}
    # Expected: (4 * 0.94 - 1) / 3 = 2.76 / 3 = 0.92
    payload = {
        "model": "test-model",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "Critical",
                "probabilities": probs,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.85,
            },
        },
    }
    evaluation = client._parse_decider_response(payload)
    assert evaluation.priority == TriagePriority.CRITICAL
    assert evaluation.confidence == pytest.approx(0.92, abs=0.01)
    assert evaluation.confidence_is_calibrated is False


def test_deterministic_parsing_priority_distribution_inconsistency_cases():
    """Verify deterministic parsing for both observed Decider priority distributions.

    Case A (Direct question style): Clear dominance on Critical (81.44%)
      (4 * 0.8144 - 1) / 3 = 0.7525 -> 75.3% confidence
    Case B (Multi-line telemetry style): Split probability between High (57.98%) and Critical (37.11%)
      (4 * 0.5798 - 1) / 3 = 0.4397 -> 44.0% confidence
    """
    client = StrandsDeciderClient()

    # Case A: Critical
    payload_crit = {
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
                "confidence": 0.7525,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.8049,
            },
        },
    }
    eval_crit = client._parse_decider_response(payload_crit)
    assert eval_crit.priority == TriagePriority.CRITICAL
    assert eval_crit.confidence == 0.7525
    assert eval_crit.confidence_is_calibrated is False
    assert eval_crit.requires_emergency_mitigation is True
    assert eval_crit.priority_probabilities["Critical"] == 0.8144

    # Case B: High
    payload_high = {
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
                "confidence": 0.4397,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.8049,
            },
        },
    }
    eval_high = client._parse_decider_response(payload_high)
    assert eval_high.priority == TriagePriority.HIGH
    assert eval_high.confidence == 0.4397
    assert eval_high.confidence_is_calibrated is False
    assert eval_high.requires_emergency_mitigation is True
    assert eval_high.priority_probabilities["High"] == 0.5798


# 4. Remote server connection refused raises StrandsDeciderUnavailableError
@pytest.mark.asyncio
async def test_remote_server_connection_refused_raises_unavailable():
    client = StrandsDeciderClient(server_url="http://127.0.0.1:59999", mode="remote", timeout_seconds=0.5)
    resp = create_sample_vuln()

    with pytest.raises(StrandsDeciderUnavailableError) as exc_info:
        await client.evaluate(resp)

    assert "Connection refused" in exc_info.value.message or "unavailable" in exc_info.value.message


# 5. Local execution offline deterministic tests
@pytest.mark.asyncio
async def test_local_execution_success_and_truthful_provenance():
    clear_local_engine_cache()
    mock_engine = MagicMock()
    mock_engine.ask.return_value = {
        "model": "strands-decider-0.1.0",  # Package name returned by SystemOneResponse.model
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "Critical",
                "probabilities": {
                    "Critical": 0.8144,
                    "High": 0.1173,
                    "Medium": 0.0471,
                    "Low": 0.0212,
                },
                "confidence": 0.7526,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.6872,
            },
        },
        "usage": {"input_tokens": 147, "output_tokens": 2},
    }

    with unittest.mock.patch("strands_decider.infer.load_engine", return_value=mock_engine) as mock_load:
        client = StrandsDeciderClient(mode="local")
        resp = create_sample_vuln()
        evaluation = await client.evaluate(resp)

        assert mock_load.called
        assert isinstance(evaluation, DeciderEvaluation)
        assert evaluation.priority == TriagePriority.CRITICAL
        # Truthful provenance: Configured checkpoint is reported, NOT package version identifier
        assert evaluation.model_id == "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610"
        assert evaluation.confidence == pytest.approx(0.7526, abs=0.001)
        assert evaluation.requires_emergency_mitigation is True
        assert evaluation.emergency_mitigation_noul == 0.6872
        assert evaluation.priority_probabilities["Critical"] == 0.8144


@pytest.mark.asyncio
async def test_local_execution_model_reuse_across_requests():
    clear_local_engine_cache()
    mock_engine = MagicMock()
    mock_engine.ask.return_value = {
        "model": "strands-decider-0.1.0",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "High",
                "probabilities": {"Critical": 0.1, "High": 0.8, "Medium": 0.05, "Low": 0.05},
                "confidence": 0.7333,
            },
            "requires_emergency_mitigation": {"type": "noul", "noul": 0.1},
        },
    }

    with unittest.mock.patch("strands_decider.infer.load_engine", return_value=mock_engine) as mock_load:
        client1 = StrandsDeciderClient(mode="local")
        client2 = StrandsDeciderClient(mode="local")
        resp = create_sample_vuln()

        eval1 = await client1.evaluate(resp)
        eval2 = await client2.evaluate(resp)

        assert eval1.priority == TriagePriority.HIGH
        assert eval2.priority == TriagePriority.HIGH
        # Model weights must be loaded only once across multiple client calls
        assert mock_load.call_count == 1


@pytest.mark.asyncio
async def test_local_execution_load_failure_security_policy_oserror():
    clear_local_engine_cache()
    with unittest.mock.patch(
        "strands_decider.infer.load_engine",
        side_effect=OSError("[WinError 4551] The operation was blocked by AppLocker"),
    ):
        client = StrandsDeciderClient(mode="local")
        resp = create_sample_vuln()

        with pytest.raises(StrandsDeciderUnavailableError) as exc_info:
            await client.evaluate(resp)

        assert "WinError 4551" in exc_info.value.message
        assert "python -m strands_decider.server" in exc_info.value.message


@pytest.mark.asyncio
async def test_local_execution_load_failure_import_error():
    clear_local_engine_cache()
    with unittest.mock.patch(
        "strands_decider.infer.load_engine",
        side_effect=ImportError("No module named 'strands_decider'"),
    ):
        client = StrandsDeciderClient(mode="local")
        resp = create_sample_vuln()

        with pytest.raises(StrandsDeciderUnavailableError) as exc_info:
            await client.evaluate(resp)

        assert "unavailable" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_local_execution_inference_failure():
    clear_local_engine_cache()
    mock_engine = MagicMock()
    mock_engine.ask.side_effect = RuntimeError("Forward pass execution failed on CPU")

    with unittest.mock.patch("strands_decider.infer.load_engine", return_value=mock_engine):
        client = StrandsDeciderClient(mode="local")
        resp = create_sample_vuln()

        with pytest.raises(StrandsDeciderError) as exc_info:
            await client.evaluate(resp)

        assert "Local Strands Decider inference failed" in exc_info.value.message


def test_local_device_resolution():
    client_cpu = StrandsDeciderClient(device="cpu")
    assert client_cpu._resolve_device() == "cpu"

    client_custom = StrandsDeciderClient(device="cuda:1")
    assert client_custom._resolve_device() == "cuda:1"

    client_auto = StrandsDeciderClient(device="auto")
    assert client_auto._resolve_device() in ("cpu", "cuda", "mps")


# 6. Injected mock engine works deterministically offline
@pytest.mark.asyncio
async def test_injected_mock_engine_works_deterministically():
    mock_payload = {
        "model": "injected-mock-decider",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "High",
                "probabilities": {"Critical": 0.1, "High": 0.85, "Medium": 0.03, "Low": 0.02},
                "confidence": 0.80,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.15,
            },
        },
    }
    mock_engine = MagicMock()
    mock_engine.ask.return_value = mock_payload

    client = StrandsDeciderClient(injected_engine=mock_engine)
    resp = create_sample_vuln(is_cisa_kev=False, cvss_score=8.0)
    evaluation = await client.evaluate(resp)

    assert evaluation.priority == TriagePriority.HIGH
    assert evaluation.confidence == 0.80
    assert evaluation.requires_emergency_mitigation is False
    assert evaluation.model_id == "injected-mock-decider"


# 7. Health check endpoint (GET /health) success and failures
@pytest.mark.asyncio
async def test_remote_server_health_check_success():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url)

    mock_health_payload = {
        "status": "ok",
        "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "checkpoint": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "base_model": "Qwen/Qwen2.5-0.5B",
        "device": "cuda:0",
        "temperature": 1.0,
    }

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.get(f"{mock_server_url}/health").respond(
            status_code=200,
            json=mock_health_payload,
        )

        health = await client.check_health()
        assert health["reachable"] is True
        assert health["status"] == "ok"
        assert health["model"] == "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610"
        assert health["device"] == "cuda:0"


@pytest.mark.asyncio
async def test_remote_server_health_check_connection_failure():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url)

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.get(f"{mock_server_url}/health").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        health = await client.check_health()
        assert health["reachable"] is False
        assert "Connection refused" in health["status"]


@pytest.mark.asyncio
async def test_remote_server_health_check_timeout():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url)

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.get(f"{mock_server_url}/health").mock(
            side_effect=httpx.TimeoutException("Health check timed out")
        )

        health = await client.check_health()
        assert health["reachable"] is False
        assert "timed out" in health["status"].lower()


@pytest.mark.asyncio
async def test_remote_server_health_check_non_200():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url)

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.get(f"{mock_server_url}/health").respond(status_code=503)

        health = await client.check_health()
        assert health["reachable"] is False
        assert "503" in health["status"]


# 8. Request schema verifies official 'instructions' and boolean noul criteria
@pytest.mark.asyncio
async def test_remote_request_schema_payload_structure():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url, mode="remote")
    resp = create_sample_vuln()

    captured_request = {}

    def capture_handler(request: httpx.Request) -> httpx.Response:
        import json
        captured_request["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            status_code=200,
            json={
                "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
                "answers": {
                    "priority": {
                        "choice": "Critical",
                        "probabilities": {"Critical": 0.99, "High": 0.01},
                        "confidence": 0.98,
                    },
                    "requires_emergency_mitigation": {
                        "noul": 0.95,
                        "probabilities": {"true": 0.95, "false": 0.05},
                    },
                },
                "latency_ms": 11.2,
            },
        )

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.post(f"{mock_server_url}/v1/systemone").mock(side_effect=capture_handler)

        evaluation = await client.evaluate(resp)
        assert evaluation.priority == TriagePriority.CRITICAL

        body = captured_request["body"]
        assert "state" in body
        assert "questions" in body
        questions = body["questions"]

        # Check official ChoiceQuestion format
        assert "priority" in questions
        assert questions["priority"]["type"] == "choice"
        assert "instructions" in questions["priority"]
        assert "Critical" in questions["priority"]["criteria"]

        # Check official NoulQuestion format (criteria keys subset of {"true", "false"})
        assert "requires_emergency_mitigation" in questions
        assert questions["requires_emergency_mitigation"]["type"] == "noul"
        assert "instructions" in questions["requires_emergency_mitigation"]
        criteria_keys = set(questions["requires_emergency_mitigation"]["criteria"].keys())
        assert criteria_keys == {"true", "false"}


# 9. Official response parsing with noul inside probabilities
def test_parse_official_response_with_noul_probabilities():
    client = StrandsDeciderClient()
    payload = {
        "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        "answers": {
            "priority": {
                "choice": "High",
                "probabilities": {"Critical": 0.05, "High": 0.90, "Medium": 0.03, "Low": 0.02},
            },
            "requires_emergency_mitigation": {
                "probabilities": {"true": 0.12, "false": 0.88},
            },
        },
        "latency_ms": 15.3,
    }

    evaluation = client._parse_decider_response(payload)
    assert evaluation.priority == TriagePriority.HIGH
    assert evaluation.requires_emergency_mitigation is False
    assert evaluation.emergency_mitigation_noul == 0.12
    assert evaluation.confidence > 0.8


# 10. Malformed response schema tests
def test_malformed_response_missing_answers():
    client = StrandsDeciderClient()
    bad_payload = {"model": "test"}
    with pytest.raises(StrandsDeciderValidationError) as exc:
        client._parse_decider_response(bad_payload)
    assert "missing 'answers'" in exc.value.message


def test_malformed_response_missing_priority():
    client = StrandsDeciderClient()
    bad_payload = {
        "model": "test",
        "answers": {
            "requires_emergency_mitigation": {"noul": 0.5},
        },
    }
    with pytest.raises(StrandsDeciderValidationError) as exc:
        client._parse_decider_response(bad_payload)
    assert "missing 'priority'" in exc.value.message


def test_malformed_response_invalid_choice():
    client = StrandsDeciderClient()
    bad_payload = {
        "model": "test",
        "answers": {
            "priority": {
                "choice": "Disastrous",
                "probabilities": {"Disastrous": 1.0},
            },
        },
    }
    with pytest.raises(StrandsDeciderValidationError) as exc:
        client._parse_decider_response(bad_payload)
    assert "invalid priority choice" in exc.value.message


def test_malformed_response_missing_probabilities():
    client = StrandsDeciderClient()
    bad_payload = {
        "model": "test",
        "answers": {
            "priority": {
                "choice": "Critical",
            },
        },
    }
    with pytest.raises(StrandsDeciderValidationError) as exc:
        client._parse_decider_response(bad_payload)
    assert "missing probabilities distribution" in exc.value.message


# 11. Remote server returns HTTP 422 Unprocessable Entity
@pytest.mark.asyncio
async def test_remote_server_http_422_validation_error():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url, mode="remote")
    resp = create_sample_vuln()

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.post(f"{mock_server_url}/v1/systemone").respond(
            status_code=422,
            text='{"detail":[{"loc":["body","questions","requires_emergency_mitigation","criteria"],"msg":"criteria keys must be subset of {\'true\', \'false\'}"}]}',
        )

        with pytest.raises(StrandsDeciderValidationError) as exc:
            await client.evaluate(resp)
        assert "HTTP 422" in exc.value.message


# 12. Remote server returns HTTP 404
@pytest.mark.asyncio
async def test_remote_server_http_404_unavailable():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url, mode="remote")
    resp = create_sample_vuln()

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.post(f"{mock_server_url}/v1/systemone").respond(status_code=404)

        with pytest.raises(StrandsDeciderUnavailableError) as exc:
            await client.evaluate(resp)
        assert "404 Not Found" in exc.value.message


# 13. Remote server returns HTTP 500 and retries before failing
@pytest.mark.asyncio
async def test_remote_server_http_500_retries_and_fails():
    mock_server_url = "http://127.0.0.1:8080"
    client = StrandsDeciderClient(server_url=mock_server_url, mode="remote", max_retries=1)
    resp = create_sample_vuln()

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.post(f"{mock_server_url}/v1/systemone").respond(
            status_code=500,
            text="Internal Server Error: CUDA out of memory",
        )

        with pytest.raises(StrandsDeciderError) as exc:
            await client.evaluate(resp)
        assert "HTTP 500" in exc.value.message or "500" in str(exc.value.status_code)


# 14. Local mode blocks automatic download when allow_local_model_download=False
def test_check_model_download_allowed_blocks_unopted_download():
    from app.services.strands_client import check_model_download_allowed

    with unittest.mock.patch("pathlib.Path.exists", return_value=False):
        with unittest.mock.patch("huggingface_hub.try_to_load_from_cache", return_value=None, create=True):
            with pytest.raises(StrandsDeciderUnavailableError) as exc:
                check_model_download_allowed("StrandsAgents/strands-decider-2B-qwen3.5-v1-2610", allow_download=False)
            assert "ALLOW_LOCAL_MODEL_DOWNLOAD=false" in exc.value.message


def test_check_host_resources_blocks_constrained_memory():
    from app.services.strands_client import check_host_resources

    mock_mem = MagicMock()
    mock_mem.available = 1024 * 1024 * 1024 * 0.5  # 512MB available (e.g. Render free tier)
    with unittest.mock.patch("psutil.virtual_memory", return_value=mock_mem):
        with pytest.raises(StrandsDeciderUnavailableError) as exc:
            check_host_resources()
        assert "Constrained host memory" in exc.value.message


# 15. Auto mode falls back to local when remote server fails
@pytest.mark.asyncio
async def test_auto_mode_falls_back_to_local_when_remote_fails():
    clear_local_engine_cache()
    mock_server_url = "http://127.0.0.1:8080"
    mock_engine = MagicMock()
    mock_engine.ask.return_value = {
        "model": "strands-decider-0.1.0",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": "Critical",
                "probabilities": {"Critical": 0.9, "High": 0.08, "Medium": 0.01, "Low": 0.01},
                "confidence": 0.85,
            },
            "requires_emergency_mitigation": {"type": "noul", "noul": 0.92},
        },
    }

    with unittest.mock.patch("strands_decider.infer.load_engine", return_value=mock_engine):
        client = StrandsDeciderClient(
            server_url=mock_server_url,
            mode="auto",
        )
        resp = create_sample_vuln()

        async with respx.mock(assert_all_called=True) as respx_mock:
            # Remote connection refused
            respx_mock.post(f"{mock_server_url}/v1/systemone").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            evaluation = await client.evaluate(resp)
            assert evaluation.priority == TriagePriority.CRITICAL
            assert evaluation.confidence == 0.85
