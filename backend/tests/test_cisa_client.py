import pytest
import respx
import httpx
from app.config import settings
from app.models.enums import SourceStatus
from app.services.cisa_client import CisaKevClient
from tests.conftest import MOCK_CISA_CATALOG


@pytest.mark.asyncio
async def test_cisa_client_listed_cve():
    client = CisaKevClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)

        result = await client.get_cve_kev_data("CVE-2021-44228")

        assert result.status == SourceStatus.LISTED
        assert result.is_listed is True
        assert result.vendor_project == "Apache"
        assert result.product == "Log4j2"
        assert result.due_date == "2021-12-24"
        assert "Confirmed listed in CISA" in result.notes


@pytest.mark.asyncio
async def test_cisa_client_unlisted_cve_preserves_non_safety_provenance():
    client = CisaKevClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)

        result = await client.get_cve_kev_data("CVE-2022-99999")

        assert result.status == SourceStatus.NOT_LISTED
        assert result.is_listed is False
        assert result.date_added is None
        assert "Not listed in CISA KEV catalog" in result.notes
        assert "does not indicate absence of risk or proof of safety" in result.notes


@pytest.mark.asyncio
async def test_cisa_client_network_failure():
    client = CisaKevClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=500)

        result = await client.get_cve_kev_data("CVE-2021-44228")

        assert result.status == SourceStatus.FAILED
        assert result.is_listed is False
        assert "500" in result.error_message or "unavailable" in result.error_message.lower()


@pytest.mark.asyncio
async def test_cisa_client_403_forbidden():
    """Verify that HTTP 403 Forbidden is classified as FAILED and never indicates unlisted."""
    client = CisaKevClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=403, text="Forbidden")

        result = await client.get_cve_kev_data("CVE-2021-44228")

        assert result.status == SourceStatus.FAILED
        assert result.is_listed is False
        assert "403" in result.error_message
        assert "upstream fetch failure" in result.notes


@pytest.mark.asyncio
async def test_cisa_client_timeout():
    """Verify that request timeout is explicitly classified as TIMEOUT."""
    client = CisaKevClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).mock(side_effect=httpx.TimeoutException("Connection timed out"))

        result = await client.get_cve_kev_data("CVE-2021-44228")

        assert result.status == SourceStatus.TIMEOUT
        assert result.is_listed is False
        assert "timed out" in result.error_message.lower()


@pytest.mark.asyncio
async def test_cisa_client_stale_cache_and_refresh_failure():
    """Verify that when cache is stale (expired TTL) and upstream refresh fails:

    1. Unlisted CVE is NEVER reported as NOT_LISTED (must be FAILED/TIMEOUT).
    2. Listed CVE in existing cache is reported as LISTED with explicit stale disclosure.
    """
    from datetime import datetime, timezone, timedelta
    client = CisaKevClient()

    # Seed client with an older cache (beyond TTL)
    client._catalog_cache = {
        "CVE-2021-44228": {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "requiredAction": "Apply vendor updates.",
        }
    }
    client._catalog_metadata = {"catalogVersion": "2021.12.10", "count": 1}
    stale_time = datetime.now(timezone.utc) - timedelta(hours=settings.cisa_cache_ttl_hours + 1)
    client._last_refreshed = stale_time

    # When refresh is attempted, upstream returns 403 Forbidden
    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=403, text="Forbidden")

        # 1. Unlisted CVE query: MUST NOT return NOT_LISTED
        unlisted_result = await client.get_cve_kev_data("CVE-2024-99999")
        assert unlisted_result.status == SourceStatus.FAILED
        assert unlisted_result.is_listed is False
        assert "stale" in unlisted_result.error_message.lower()
        assert "cannot be confirmed" in unlisted_result.notes.lower()

        # 2. Listed CVE query: returns LISTED with notes detailing upstream failure
        listed_result = await client.get_cve_kev_data("CVE-2021-44228")
        assert listed_result.status == SourceStatus.LISTED
        assert listed_result.is_listed is True
        assert listed_result.error_message is not None
        assert "upstream refresh failed" in listed_result.error_message.lower()
        assert "upstream refresh failed" in listed_result.notes.lower()


@pytest.mark.asyncio
async def test_cisa_client_successful_refresh():
    """Verify that successful refresh updates timestamp, catalog version, and clears error state."""
    client = CisaKevClient()
    client._last_refresh_error = "Previous error"
    client._last_refresh_status = SourceStatus.FAILED

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)

        result = await client.get_cve_kev_data("CVE-2021-44228")

        assert result.status == SourceStatus.LISTED
        assert result.is_listed is True
        assert result.error_message is None
        assert client._last_refresh_error is None
        assert client._last_refresh_status is None
        assert client.metadata["is_stale"] is False
        assert client.count > 0


@pytest.mark.asyncio
async def test_cisa_client_headers_contain_user_agent():
    """Verify that CISA client passes standard User-Agent and Accept headers."""
    client = CisaKevClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        route = respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)

        await client.ensure_catalog()

        assert route.called
        last_request = route.calls.last.request
        assert "user-agent" in last_request.headers
        assert "ThreatPrior-AI" in last_request.headers["user-agent"]
        assert "application/json" in last_request.headers.get("accept", "")
