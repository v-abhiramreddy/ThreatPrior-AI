import pytest
import respx
import httpx
from app.config import settings
from app.models.enums import SourceStatus
from app.services.epss_client import EpssClient
from tests.conftest import MOCK_EPSS_LOG4SHELL, MOCK_EPSS_EMPTY


@pytest.mark.asyncio
async def test_epss_client_success():
    client = EpssClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        result = await client.get_epss_data("CVE-2021-44228")

        assert result.status == SourceStatus.AVAILABLE
        assert result.probability == 0.97410
        assert result.percentile == 0.99800
        assert result.score_date == "2026-10-15"
        assert "Estimated probability of active exploitation" in result.interpretive_note


@pytest.mark.asyncio
async def test_epss_client_not_found():
    client = EpssClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_EMPTY)

        result = await client.get_epss_data("CVE-1999-0001")

        assert result.status == SourceStatus.NOT_FOUND
        assert result.probability is None
        assert result.percentile is None


@pytest.mark.asyncio
async def test_epss_client_timeout():
    client = EpssClient(timeout=0.1)

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.epss_api_url).mock(side_effect=httpx.TimeoutException("Read timed out"))

        result = await client.get_epss_data("CVE-2021-44228")

        assert result.status == SourceStatus.TIMEOUT
        assert "timed out" in result.error_message.lower()
