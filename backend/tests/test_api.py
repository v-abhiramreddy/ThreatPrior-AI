import pytest
import respx
import httpx
from app.main import app
from app.config import settings
from app.services.cisa_client import cisa_client
from tests.conftest import (
    MOCK_CISA_CATALOG,
    MOCK_NVD_LOG4SHELL,
    MOCK_EPSS_LOG4SHELL,
)


@pytest.mark.asyncio
async def test_api_valid_cve():
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2021-44228")

            assert response.status_code == 200
            data = response.json()
            assert data["cve_id"] == "CVE-2021-44228"
            assert data["status"] == "OK"
            assert data["normalized"]["cvss_score"] == 10.0
            assert data["normalized"]["is_cisa_kev"] is True
            assert data["normalized"]["epss_probability"] == 0.97410
            assert data["provenance"]["nvd"]["source"] == "NIST National Vulnerability Database API v2.0"
            assert data["provenance"]["cisa_kev"]["source"] == "CISA Known Exploited Vulnerabilities Catalog"
            assert data["provenance"]["epss"]["source"] == "FIRST.org EPSS API v3"


@pytest.mark.asyncio
async def test_api_invalid_cve_format():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Invalid prefix / malformed formats
        for invalid in ["not-a-cve", "CVE-2021", "CVE-ABCD-1234", "CVE-2021-12", "'; DROP TABLE;--"]:
            response = await client.get(f"/api/vulnerabilities/{invalid}")
            assert response.status_code == 400
            data = response.json()
            assert "Invalid CVE identifier" in data["detail"]


@pytest.mark.asyncio
async def test_api_unknown_cve_returns_404():
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(
            status_code=200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        )
        respx_mock.get(settings.epss_api_url).respond(
            status_code=200, json={"status": "OK", "total": 0, "data": []}
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2099-99999")
            assert response.status_code == 404
            data = response.json()
            assert data["status"] == "NOT_FOUND"
            assert data["normalized"] is None


@pytest.mark.asyncio
async def test_api_insufficient_evidence_when_cisa_fails():
    """Verify that when NVD & EPSS report not found but CISA fails,

    GET /api/vulnerabilities/{cve} returns 502 with ERROR status and normalized=None.
    """
    cisa_client._catalog_cache.clear()
    cisa_client._last_refreshed = None

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=403, text="Forbidden")
        respx_mock.get(settings.nvd_api_base_url).respond(
            status_code=200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        )
        respx_mock.get(settings.epss_api_url).respond(
            status_code=200, json={"status": "OK", "total": 0, "data": []}
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/vulnerabilities/CVE-2099-99999")
            assert response.status_code == 502
            data = response.json()
            assert data["status"] == "ERROR"
            assert data["normalized"] is None
            assert data["provenance"]["cisa_kev"]["status"] == "FAILED"
            assert data["provenance"]["nvd"]["status"] == "NOT_FOUND"
            assert data["provenance"]["epss"]["status"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_cors_preflight_valid_origin():
    """Verify that CORS preflight from allowed origin succeeds with credentials allowed."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert response.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_cors_preflight_invalid_origin():
    """Verify that CORS preflight from unconfigured/untrusted origin is rejected."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.options(
            "/api/health",
            headers={
                "Origin": "http://untrusted-attacker.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # CORSMiddleware does not reflect the origin or rejects with 400
        assert (
            "access-control-allow-origin" not in response.headers
            or response.headers["access-control-allow-origin"] != "http://untrusted-attacker.example.com"
        )
