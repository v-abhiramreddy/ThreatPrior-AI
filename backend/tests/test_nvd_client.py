import pytest
import respx
import httpx
from app.config import settings
from app.models.enums import SourceStatus, SeverityLevel
from app.services.nvd_client import NvdClient
from tests.conftest import MOCK_NVD_LOG4SHELL, MOCK_NVD_CVSS_V2_ONLY


@pytest.mark.asyncio
async def test_nvd_client_success():
    client = NvdClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)

        result = await client.get_cve_data("CVE-2021-44228")

        assert result.status == SourceStatus.AVAILABLE
        assert result.cvss_v31 is not None
        assert result.cvss_v31.base_score == 10.0
        assert result.cvss_v31.severity == SeverityLevel.CRITICAL
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" in result.cvss_v31.vector_string
        assert "CWE-502" in result.weaknesses
        assert any("cpe:2.3:a:apache:log4j" in cpe for cpe in result.cpe_configurations)


@pytest.mark.asyncio
async def test_nvd_client_cvss_v2_fallback():
    client = NvdClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_CVSS_V2_ONLY)

        result = await client.get_cve_data("CVE-2008-0001")

        assert result.status == SourceStatus.AVAILABLE
        assert result.cvss_v31 is None
        assert result.cvss_v20 is not None
        assert result.cvss_v20.base_score == 7.5
        assert result.cvss_v20.severity == SeverityLevel.HIGH


@pytest.mark.asyncio
async def test_nvd_client_zero_results():
    client = NvdClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.nvd_api_base_url).respond(
            status_code=200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        )

        result = await client.get_cve_data("CVE-2099-0000")

        assert result.status == SourceStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_nvd_client_rate_limited():
    client = NvdClient()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=429, headers={"Retry-After": "1"})

        result = await client.get_cve_data("CVE-2021-44228")

        assert result.status == SourceStatus.RATE_LIMITED
        assert "rate limit" in result.error_message.lower()


@pytest.mark.asyncio
async def test_nvd_client_timeout():
    client = NvdClient(timeout=0.1)

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.nvd_api_base_url).mock(side_effect=httpx.TimeoutException("Read timed out"))

        result = await client.get_cve_data("CVE-2021-44228")

        assert result.status == SourceStatus.TIMEOUT
        assert "timed out" in result.error_message.lower()
