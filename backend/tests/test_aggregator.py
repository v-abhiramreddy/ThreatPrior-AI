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
        assert res.normalized.summary is not None
        assert len(res.normalized.summary) > 0

        # Provenance verification
        assert res.provenance.nvd.status == SourceStatus.AVAILABLE
        assert res.provenance.cisa_kev.status == SourceStatus.LISTED
        assert res.provenance.epss.status == SourceStatus.AVAILABLE


def test_generate_operational_summary_distinct():
    from app.services.aggregator import generate_operational_summary

    long_nvd_desc = (
        "Apache Log4j2 versions 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) "
        "JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP "
        "and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute "
        "arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior "
        "has been disabled by default. In version 2.16.0, this functionality has been completely removed. Note that this "
        "vulnerability is specific to log4j-core and does not affect log4net or log4cxx."
    )

    summary = generate_operational_summary(long_nvd_desc, "Log4Shell", "CVE-2021-44228")
    assert summary is not None
    assert len(summary) > 0
    assert summary != long_nvd_desc
    assert len(summary) < len(long_nvd_desc)
    # Does not copy the opening sentence
    assert not summary.startswith("Apache Log4j2 versions 2.0-beta9")
    assert "arbitrary code" in summary
    assert "practical risk" in summary

    # Fallback behavior when reliable summary cannot be synthesized
    fallback = generate_operational_summary("Generic issue without standard impact", "Sparse CVE", "CVE-2099-0001")
    assert "Operational Summary Fallback:" in fallback
    assert "authoritative Technical Description below" in fallback


def test_generate_operational_summary_cve_2024_3094_backdoor():
    """Verify operational summary synthesis for CVE-2024-3094 XZ Utils supply chain backdoor."""
    from app.services.aggregator import generate_operational_summary

    xz_nvd_desc = (
        "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. "
        "Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file "
        "from a disguised test file existing in the source code, which is then used to modify specific functions "
        "in the liblzma code. This results in a modified liblzma library that can be used by any software linked "
        "against this library, intercepting and modifying the data interaction with this library."
    )

    summary = generate_operational_summary(xz_nvd_desc, "XZ Utils (CVE-2024-3094)", "CVE-2024-3094")
    assert summary is not None
    assert "Operational Summary Fallback:" not in summary
    assert "malicious code" in summary
    assert "XZ Utils" in summary
    assert "5.6.0" in summary
    assert "unauthorized function interception" in summary
    assert "remote authentication bypass" in summary
    assert "compromised components were used" in summary
    assert not summary.startswith("Malicious code was discovered")

    # With CPE configurations explicitly preserving both 5.6.0 and 5.6.1
    cpes = ["cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"]
    summary_cpe = generate_operational_summary(xz_nvd_desc, "XZ Utils (CVE-2024-3094)", "CVE-2024-3094", cpe_configurations=cpes)
    assert "5.6.0 and 5.6.1" in summary_cpe
    assert "upstream releases (5.6.0 and 5.6.1) of XZ Utils" in summary_cpe
    assert "compromised components were used" in summary_cpe


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
