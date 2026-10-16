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
        assert "unavailable" in result.error_message.lower()
