import json
from unittest.mock import MagicMock
import pytest
import respx
import httpx

from app.main import app
from app.config import settings
from app.models.triage import ModelInvocationStatus, TriagePriority
from app.services.decision_engine import decision_engine
from app.services.cisa_client import cisa_client
from app.services.strands_client import StrandsDeciderClient, StrandsDeciderUnavailableError
from tests.conftest import (
    MOCK_CISA_CATALOG,
    MOCK_NVD_LOG4SHELL,
    MOCK_EPSS_LOG4SHELL,
)


def create_mock_decider(priority: str = "Critical", confidence: float = 0.96) -> StrandsDeciderClient:
    mock_engine = MagicMock()
    mock_engine.ask.return_value = {
        "model": "strands-decider-2b",
        "answers": {
            "priority": {
                "type": "choice",
                "choice": priority,
                "probabilities": {"Critical": 0.97, "High": 0.01, "Medium": 0.01, "Low": 0.01},
                "confidence": confidence,
            },
            "requires_emergency_mitigation": {
                "type": "noul",
                "noul": 0.99,
            },
        },
    }
    return StrandsDeciderClient(injected_engine=mock_engine)


@pytest.mark.asyncio
async def test_triage_api_returns_dual_ai_decision(monkeypatch):
    # Mock upstream threat intel sources with respx
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        # Mock Decider Client
        mock_decider = create_mock_decider(priority="Critical", confidence=0.96)
        monkeypatch.setattr(decision_engine, "strands_client", mock_decider)

        # Mock Bedrock client
        mock_bedrock = MagicMock()
        mock_payload = {
            "priority": "Critical",
            "rationale": "Log4Shell is actively weaponized and listed in CISA KEV with CVSS 10.0.",
            "risk_factors": ["CISA KEV Listed", "CVSS 10.0 Network vector", "High EPSS"],
            "recommended_action": "Apply immediate mitigation per vendor guidance.",
            "evidence_limitations": ["EPSS represents 30-day weaponization forecast."],
        }
        mock_bedrock.converse.return_value = {
            "output": {"message": {"content": [{"text": json.dumps(mock_payload)}]}}
        }
        monkeypatch.setattr(decision_engine, "_injected_client", mock_bedrock)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert response.status_code == 200
            data = response.json()

            assert data["cve_id"] == "CVE-2021-44228"
            assert data["status"] == "OK"
            assert "decision" in data
            decision = data["decision"]
            assert decision["priority"] == "Critical"
            assert decision["engine"] == "dual-ai"
            assert decision["decider_model_id"] == "strands-decider-2b"
            assert decision["bedrock_model_id"] == settings.bedrock_model_id
            assert decision["decider_status"] == "success"
            assert decision["bedrock_status"] == "success"
            assert decision["confidence_is_calibrated"] is False
            assert decision["confidence"] == 0.96
            assert decision["recommendation_source"] == "bedrock_synthesis"
            assert decision["recommendation_is_verified"] is False
            assert decision["authoritative_directive"] is not None
            assert decision["authoritative_directive_source"] == "cisa_kev"
            assert len(decision["risk_factors"]) == 3

            # Risk validation must be present
            assert "risk_validation" in data
            assert data["risk_validation"] is not None
            assert data["risk_validation"]["model_priority"] == "Critical"
            assert data["risk_validation"]["evidence_priority"] == "Critical"
            assert data["risk_validation"]["risk_validation_status"] == "aligned"
            assert data["risk_validation"]["validation_rules_version"] == "2026.1-policy"
            assert len(data["risk_validation"]["risk_factors"]) >= 3

            # Provenance must be intact
            assert data["provenance"]["nvd"]["status"] == "AVAILABLE"
            assert data["provenance"]["cisa_kev"]["status"] == "LISTED"
            assert data["provenance"]["epss"]["status"] == "AVAILABLE"


@pytest.mark.asyncio
async def test_triage_api_decider_only_degraded_mode(monkeypatch):
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        # Decider succeeds
        mock_decider = create_mock_decider(priority="Critical", confidence=0.93)
        monkeypatch.setattr(decision_engine, "strands_client", mock_decider)

        # Bedrock fails
        mock_bedrock = MagicMock()
        mock_bedrock.converse.side_effect = Exception("AWS Bedrock rate limit exceeded")
        monkeypatch.setattr(decision_engine, "_injected_client", mock_bedrock)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert response.status_code == 200
            data = response.json()
            decision = data["decision"]

            assert decision["engine"] == "decider-only"
            assert decision["decider_model_id"] == "strands-decider-2b"
            assert decision["bedrock_model_id"] is None
            assert decision["decider_status"] == "success"
            assert decision["bedrock_status"] == "failed"
            assert decision["confidence_is_calibrated"] is False
            assert decision["confidence"] == 0.93
            assert decision["recommendation_source"] == "cisa_kev_directive"
            assert decision["recommendation_is_verified"] is True
            assert decision["recommendation_url"] is None
            assert data["risk_validation"] is not None
            assert data["risk_validation"]["evidence_priority"] == "Critical"
            assert data["risk_validation"]["model_priority"] == "Critical"
            assert data["risk_validation"]["risk_validation_status"] == "aligned"


@pytest.mark.asyncio
async def test_triage_api_baseline_fallback_labeled_explicitly(monkeypatch):
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        # Force Decider error
        failing_decider = MagicMock()
        failing_decider.evaluate.side_effect = StrandsDeciderUnavailableError(
            "Strands Decider server connection refused on http://127.0.0.1:8080"
        )
        monkeypatch.setattr(decision_engine, "strands_client", failing_decider)
        monkeypatch.setattr(decision_engine, "allow_fallback", True)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert response.status_code == 200
            data = response.json()
            decision = data["decision"]

            # Must be labeled as baseline, NOT dual-ai
            assert decision["engine"] == "baseline"
            assert decision["model_id"] == "baseline-heuristic-v1"
            assert decision["decider_model_id"] is None
            assert decision["bedrock_model_id"] is None
            assert decision["confidence_is_calibrated"] is False
            assert "Strands Decider 2B unavailable" in (decision["fallback_reason"] or "")
            assert data["risk_validation"] is not None
            assert data["risk_validation"]["evidence_priority"] == "Critical"
            assert data["risk_validation"]["model_priority"] == "Critical"
            assert data["risk_validation"]["risk_validation_status"] == "aligned"


@pytest.mark.asyncio
async def test_triage_api_invalid_cve_format():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/vulnerabilities/bad-cve/triage")
        assert response.status_code == 400
        assert "Invalid CVE identifier" in response.json()["detail"]


@pytest.mark.asyncio
async def test_triage_api_unknown_cve_returns_404():
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(
            status_code=200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        )
        respx_mock.get(settings.epss_api_url).respond(
            status_code=200, json={"status": "OK", "total": 0, "data": []}
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2099-99999/triage")
            assert response.status_code == 404
            data = response.json()
            assert data["status"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_triage_api_insufficient_evidence_when_cisa_fails():
    """Verify that when NVD & EPSS report not found but CISA fails,

    the API returns HTTP 502 (Bad Gateway) with engine='unavailable'
    and NEVER returns a fake vulnerability or low-priority heuristic.
    """
    cisa_client._catalog_cache.clear()
    cisa_client._last_refreshed = None

    async with respx.mock(assert_all_called=False) as respx_mock:
        # CISA fails (e.g. 403 Forbidden or network outage)
        respx_mock.get(settings.cisa_kev_url).respond(status_code=403, text="Forbidden")
        # NVD confirms no record
        respx_mock.get(settings.nvd_api_base_url).respond(
            status_code=200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        )
        # EPSS confirms no record
        respx_mock.get(settings.epss_api_url).respond(
            status_code=200, json={"status": "OK", "total": 0, "data": []}
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2099-99999/triage")
            # Must be 502 Bad Gateway, NEVER 200 with fake Low priority
            assert response.status_code == 502
            data = response.json()

            assert data["status"] == "ERROR"
            assert data["engine"] == "unavailable"
            assert "decision" not in data  # No fabricated decision
            assert "detail" in data
            assert "Insufficient evidence" in data["detail"]
            assert "CISA KEV check failed" in data["detail"]

            # Provenance must accurately reflect each source
            assert data["provenance"]["nvd"]["status"] == "NOT_FOUND"
            assert data["provenance"]["epss"]["status"] == "NOT_FOUND"
            assert data["provenance"]["cisa_kev"]["status"] == "FAILED"
            assert len(data["errors"]) > 0


@pytest.mark.asyncio
async def test_triage_api_decider_unavailable_with_fallback_disabled(monkeypatch):
    """When allow_fallback=False and Strands Decider fails, API returns HTTP 503."""
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        failing_decider = MagicMock()
        failing_decider.evaluate.side_effect = StrandsDeciderUnavailableError(
            "Strands Decider server connection refused on http://127.0.0.1:8080"
        )
        monkeypatch.setattr(decision_engine, "strands_client", failing_decider)
        monkeypatch.setattr(decision_engine, "allow_fallback", False)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert response.status_code == 503
            data = response.json()
            assert data["engine"] == "unavailable"
            assert "Strands Decider" in data["detail"]


@pytest.mark.asyncio
async def test_triage_api_rate_limiting(monkeypatch):
    """Verify that excessive triage requests receive HTTP 429 with Retry-After header."""
    from app.routers.triage import triage_rate_limiter

    triage_rate_limiter.clear()
    monkeypatch.setattr(settings, "triage_rate_limit_per_minute", 2)

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        mock_decider = create_mock_decider(priority="Critical", confidence=0.96)
        monkeypatch.setattr(decision_engine, "strands_client", mock_decider)
        monkeypatch.setattr(decision_engine, "allow_fallback", True)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            r1 = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert r1.status_code == 200

            r2 = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert r2.status_code == 200

            # 3rd request exceeds limit of 2/min
            r3 = await client.get("/api/vulnerabilities/CVE-2021-44228/triage")
            assert r3.status_code == 429
            assert "Rate limit exceeded" in r3.json()["detail"]
            assert "Retry-After" in r3.headers

    triage_rate_limiter.clear()
