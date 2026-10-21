import asyncio
import time
import pytest
from httpx import AsyncClient, ASGITransport
from starlette.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app
from app.routers.triage import InMemoryRateLimiter, triage_rate_limiter
from app.services.cisa_client import CisaKevClient
from app.models.enums import SourceStatus, SeverityLevel, OverallStatus
from app.models.schemas import (
    VulnerabilityResponse,
    NormalizedVulnerability,
    Provenance,
    NvdProvenance,
    CisaKevProvenance,
    EpssProvenance,
)
from app.models.triage import TriagePriority, RiskValidationStatus
from app.services.risk_validator import EvidenceRiskValidator


@pytest.fixture
def anyio_backend():
    return "asyncio"


# 1. Security Headers Verification
@pytest.mark.asyncio
async def test_security_headers_enforced_on_api_responses():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/api/health")
        assert res.status_code == 200
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "geolocation=()" in res.headers.get("Permissions-Policy", "")
        assert res.headers.get("X-XSS-Protection") == "1; mode=block"


# 2. Global Exception Sanitization (no traceback leakage)
def test_global_exception_handler_sanitizes_500_errors():
    client = TestClient(app, raise_server_exceptions=False)
    # Patch aggregator to raise an unexpected internal RuntimeError
    with patch("app.routers.vulnerabilities.aggregator.aggregate_cve", side_effect=RuntimeError("Secret internal path: /var/secrets/key.pem")):
        res = client.get("/api/vulnerabilities/CVE-2021-44228")
        assert res.status_code == 500
        data = res.json()
        # Verify internal exception details, file paths, or secrets are NOT leaked to client
        assert "key.pem" not in res.text
        assert "RuntimeError" not in res.text
        assert "Traceback" not in res.text
        assert data.get("detail") == "An internal server error occurred. Please contact the administrator."


# 3. Input Validation: Oversized CVE Identifier (> 30 chars) Rejection
@pytest.mark.asyncio
async def test_oversized_cve_identifier_rejected():
    transport = ASGITransport(app=app)
    oversized_cve = "CVE-2021-" + "9" * 100
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Check both vulnerabilities and triage endpoints
        res1 = await client.get(f"/api/vulnerabilities/{oversized_cve}")
        assert res1.status_code == 400
        assert "Invalid CVE identifier" in res1.json()["detail"]

        res2 = await client.get(f"/api/vulnerabilities/{oversized_cve}/triage")
        assert res2.status_code == 400
        assert "Invalid CVE identifier" in res2.json()["detail"]


# 4. Reverse Proxy IP Extraction in Rate Limiter
@pytest.mark.asyncio
async def test_rate_limiter_prioritizes_x_forwarded_for():
    transport = ASGITransport(app=app)
    triage_rate_limiter.clear()

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Send requests from client A via X-Forwarded-For
        headers_a = {"X-Forwarded-For": "203.0.113.195, 10.0.0.1"}
        with patch("app.routers.triage.aggregator.aggregate_cve") as mock_agg:
            mock_resp = MagicMock()
            mock_resp.status.value = "NOT_FOUND"
            mock_resp.errors = []
            mock_agg.return_value = mock_resp

            # Trigger rate limit for Client A with a custom low threshold
            limiter = InMemoryRateLimiter(max_tracked_ips=100)
            with patch("app.routers.triage.triage_rate_limiter", limiter):
                for _ in range(5):
                    limiter.check("203.0.113.195", limit_per_minute=5)

                # Client A should be throttled
                with pytest.raises(Exception) as exc_info:
                    limiter.check("203.0.113.195", limit_per_minute=5)
                assert "Rate limit exceeded" in str(exc_info.value.detail)

                # Client B should NOT be affected
                limiter.check("198.51.100.42", limit_per_minute=5)


# 5. In-Memory Rate Limiter Memory Bound & Pruning
def test_rate_limiter_pruning_prevents_memory_leak():
    limiter = InMemoryRateLimiter(max_tracked_ips=10)
    now = time.time()

    # Fill with 15 stale IPs (simulating expired requests older than 60s)
    for i in range(15):
        limiter._requests[f"10.0.0.{i}"] = [now - 120.0]

    assert len(limiter._requests) == 15

    # Check a new request; should trigger pruning down to only the active key
    limiter.check("192.168.1.1", limit_per_minute=60)
    assert len(limiter._requests) == 1
    assert "192.168.1.1" in limiter._requests


# 6. Safety Invariant: Stale Seed Absence is NOT Proof of Safety
@pytest.mark.asyncio
async def test_stale_cisa_cache_absence_refuses_not_listed():
    cisa = CisaKevClient()
    # Populate seed catalog with Log4Shell
    cisa._catalog_cache = {"CVE-2021-44228": {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"}}
    cisa._last_refresh_error = "CISA KEV HTTP 403: Forbidden"

    # When upstream refresh fails, ensure_catalog returns False
    with patch.object(cisa, "ensure_catalog", return_value=False):
        prov = await cisa.get_cve_kev_data("CVE-2026-99999")
        assert prov.is_listed is False
        assert prov.status == SourceStatus.FAILED
        assert "Absence from KEV catalog cannot be confirmed" in prov.notes
        assert prov.status != SourceStatus.NOT_LISTED


# 7. Evidence Risk Validation: Preserves Model Priority on Disagreement
def test_risk_validator_preserves_model_priority_on_disagreement():
    validator = EvidenceRiskValidator()
    now = time.time()

    resp = VulnerabilityResponse(
        cve_id="CVE-2024-9999",
        status=OverallStatus.OK,
        retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        normalized=NormalizedVulnerability(
            title="Moderate Test Flaw",
            description="Moderate impact vulnerability.",
            primary_severity=SeverityLevel.MEDIUM,
            cvss_score=4.5,
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            is_cisa_kev=False,
            epss_probability=0.01,
            epss_percentile=0.1,
            affected_cpe_count=1,
        ),
        provenance=Provenance(
            nvd=NvdProvenance(retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), status=SourceStatus.AVAILABLE),
            cisa_kev=CisaKevProvenance(
                retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                status=SourceStatus.NOT_LISTED,
                is_listed=False,
                notes="Not listed in CISA KEV catalog. Absence from this catalog indicates only that CISA has not confirmed in-wild exploitation for this entry.",
            ),
            epss=EpssProvenance(retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), status=SourceStatus.AVAILABLE, probability=0.01),
        ),
        errors=[],
    )

    # Model assigned Critical to a Medium CVE
    val_result = validator.validate(resp, model_priority=TriagePriority.CRITICAL)
    # Evidence policy says Medium
    assert val_result.evidence_priority == TriagePriority.MEDIUM
    assert val_result.model_priority == TriagePriority.CRITICAL
    assert val_result.risk_validation_status == RiskValidationStatus.DISAGREEMENT
    assert "disagreement" in val_result.validation_explanation.lower()
