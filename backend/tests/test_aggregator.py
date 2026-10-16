import pytest
import respx
from app.config import settings
from app.models.enums import OverallStatus, SeverityLevel, SourceStatus
from app.services.aggregator import VulnerabilityAggregator
from tests.conftest import (
    MOCK_CISA_CATALOG,
    MOCK_NVD_LOG4SHELL,
    MOCK_EPSS_LOG4SHELL,
)


@pytest.mark.asyncio
async def test_aggregator_full_success():
    aggregator = VulnerabilityAggregator()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=200, json=MOCK_NVD_LOG4SHELL)
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        res = await aggregator.aggregate_cve("CVE-2021-44228")

        assert res.cve_id == "CVE-2021-44228"
        assert res.status == OverallStatus.OK
        assert len(res.errors) == 0

        # Normalized summary checks
        assert res.normalized is not None
        assert res.normalized.cvss_score == 10.0
        assert res.normalized.primary_severity == SeverityLevel.CRITICAL
        assert res.normalized.is_cisa_kev is True
        assert res.normalized.epss_probability == 0.97410
        assert res.normalized.affected_cpe_count == 1

        # Provenance verification
        assert res.provenance.nvd.status == SourceStatus.AVAILABLE
        assert res.provenance.cisa_kev.status == SourceStatus.LISTED
        assert res.provenance.epss.status == SourceStatus.AVAILABLE


@pytest.mark.asyncio
async def test_aggregator_partial_failure_nvd_rate_limited():
    aggregator = VulnerabilityAggregator()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(status_code=429, headers={"Retry-After": "1"})
        respx_mock.get(settings.epss_api_url).respond(status_code=200, json=MOCK_EPSS_LOG4SHELL)

        res = await aggregator.aggregate_cve("CVE-2021-44228")

        assert res.status == OverallStatus.PARTIAL
        assert len(res.errors) == 1
        assert "NVD" in res.errors[0]

        # Normalized values still deliver CISA and EPSS
        assert res.normalized is not None
        assert res.normalized.is_cisa_kev is True
        assert res.normalized.epss_probability == 0.97410
        assert res.normalized.cvss_score is None

        # Provenance records the exact rate limit status
        assert res.provenance.nvd.status == SourceStatus.RATE_LIMITED
        assert res.provenance.cisa_kev.status == SourceStatus.LISTED
        assert res.provenance.epss.status == SourceStatus.AVAILABLE


@pytest.mark.asyncio
async def test_aggregator_all_sources_unknown():
    aggregator = VulnerabilityAggregator()

    async with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(settings.cisa_kev_url).respond(status_code=200, json=MOCK_CISA_CATALOG)
        respx_mock.get(settings.nvd_api_base_url).respond(
            status_code=200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        )
        respx_mock.get(settings.epss_api_url).respond(
            status_code=200, json={"status": "OK", "total": 0, "data": []}
        )

        res = await aggregator.aggregate_cve("CVE-2099-9999")

        assert res.status == OverallStatus.NOT_FOUND
        assert res.normalized is None
        assert res.provenance.nvd.status == SourceStatus.NOT_FOUND
        assert res.provenance.cisa_kev.status == SourceStatus.NOT_LISTED
        assert res.provenance.epss.status == SourceStatus.NOT_FOUND
