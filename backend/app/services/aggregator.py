import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List
import httpx

from app.models.enums import SourceStatus, OverallStatus, SeverityLevel
from app.models.schemas import (
    VulnerabilityResponse,
    NormalizedVulnerability,
    Provenance,
    NvdProvenance,
    CisaKevProvenance,
    EpssProvenance,
)
from app.services.nvd_client import nvd_client
from app.services.cisa_client import cisa_client
from app.services.epss_client import epss_client

logger = logging.getLogger(__name__)


class VulnerabilityAggregator:
    """Aggregates and normalizes threat intelligence across NVD, CISA KEV, and EPSS."""

    async def aggregate_cve(
        self, cve_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> VulnerabilityResponse:
        now = datetime.now(timezone.utc)
        normalized_cve = cve_id.strip().upper()

        should_close = False
        if client is None:
            client = httpx.AsyncClient()
            should_close = True

        try:
            # Query all three sources concurrently
            nvd_res, cisa_res, epss_res = await asyncio.gather(
                nvd_client.get_cve_data(normalized_cve, client=client),
                cisa_client.get_cve_kev_data(normalized_cve, client=client),
                epss_client.get_epss_data(normalized_cve, client=client),
                return_exceptions=True,
            )

            # Defensive handling of unhandled exceptions
            if isinstance(nvd_res, Exception):
                logger.error("Exception from NVD client: %s", str(nvd_res))
                nvd_res = NvdProvenance(
                    retrieved_at=now,
                    status=SourceStatus.FAILED,
                    error_message=f"NVD service exception: {str(nvd_res)}",
                )

            if isinstance(cisa_res, Exception):
                logger.error("Exception from CISA client: %s", str(cisa_res))
                cisa_res = CisaKevProvenance(
                    retrieved_at=now,
                    status=SourceStatus.FAILED,
                    is_listed=False,
                    notes="CISA KEV query encountered an internal error.",
                    error_message=f"CISA KEV exception: {str(cisa_res)}",
                )

            if isinstance(epss_res, Exception):
                logger.error("Exception from EPSS client: %s", str(epss_res))
                epss_res = EpssProvenance(
                    retrieved_at=now,
                    status=SourceStatus.FAILED,
                    error_message=f"EPSS service exception: {str(epss_res)}",
                )

            provenance = Provenance(
                nvd=nvd_res,
                cisa_kev=cisa_res,
                epss=epss_res,
            )

            # Collect source-level errors
            errors: List[str] = []
            if nvd_res.error_message and nvd_res.status not in (SourceStatus.AVAILABLE, SourceStatus.NOT_FOUND):
                errors.append(f"NVD: {nvd_res.error_message}")
            if cisa_res.error_message and cisa_res.status not in (SourceStatus.LISTED, SourceStatus.NOT_LISTED):
                errors.append(f"CISA KEV: {cisa_res.error_message}")
            if epss_res.error_message and epss_res.status not in (SourceStatus.AVAILABLE, SourceStatus.NOT_FOUND):
                errors.append(f"EPSS: {epss_res.error_message}")

            # Check if all sources report unknown / not found
            all_not_found = (
                nvd_res.status == SourceStatus.NOT_FOUND
                and cisa_res.status == SourceStatus.NOT_LISTED
                and epss_res.status == SourceStatus.NOT_FOUND
            )

            if all_not_found:
                return VulnerabilityResponse(
                    cve_id=normalized_cve,
                    status=OverallStatus.NOT_FOUND,
                    retrieved_at=now,
                    normalized=None,
                    provenance=provenance,
                    errors=["No record of this CVE identifier was found in NVD, CISA KEV, or EPSS."],
                )

            # Check for insufficient evidence when registries have no record but CISA was unavailable
            nvd_and_epss_not_found = (
                nvd_res.status == SourceStatus.NOT_FOUND
                and epss_res.status == SourceStatus.NOT_FOUND
            )
            cisa_unavailable = cisa_res.status in (
                SourceStatus.FAILED,
                SourceStatus.TIMEOUT,
                SourceStatus.RATE_LIMITED,
            )

            if nvd_and_epss_not_found and cisa_unavailable:
                errors.append(
                    f"No record found in NVD or EPSS for {normalized_cve}, but CISA KEV check failed. "
                    "Evidence is insufficient to confirm absence or evaluate risk."
                )

            # Determine overall status
            any_success = (
                nvd_res.status == SourceStatus.AVAILABLE
                or cisa_res.status == SourceStatus.LISTED
                or epss_res.status == SourceStatus.AVAILABLE
            )

            if not any_success and errors:
                overall_status = OverallStatus.ERROR
            elif errors:
                overall_status = OverallStatus.PARTIAL
            else:
                overall_status = OverallStatus.OK

            # Synthesize normalized representation
            title = cisa_res.vulnerability_name or f"Vulnerability {normalized_cve}"
            description = (
                nvd_res.description
                or (cisa_res.notes if cisa_res and cisa_res.notes else None)
                or (nvd_res.weaknesses[0] if nvd_res.weaknesses else None)
                or "Vulnerability description telemetry indexed."
            )
            # NVD description is populated during NVD query
            # We also synthesize CVSS metrics from highest version available
            cvss_score = None
            cvss_version = None
            cvss_vector = None
            primary_severity = SeverityLevel.UNKNOWN

            if nvd_res.cvss_v31:
                cvss_score = nvd_res.cvss_v31.base_score
                cvss_version = "3.1"
                cvss_vector = nvd_res.cvss_v31.vector_string
                primary_severity = nvd_res.cvss_v31.severity
            elif nvd_res.cvss_v30:
                cvss_score = nvd_res.cvss_v30.base_score
                cvss_version = "3.0"
                cvss_vector = nvd_res.cvss_v30.vector_string
                primary_severity = nvd_res.cvss_v30.severity
            elif nvd_res.cvss_v20:
                cvss_score = nvd_res.cvss_v20.base_score
                cvss_version = "2.0"
                cvss_vector = nvd_res.cvss_v20.vector_string
                primary_severity = nvd_res.cvss_v20.severity

            # Build normalized payload if at least one data source provided telemetry
            normalized = None
            if any_success or nvd_res.status == SourceStatus.AVAILABLE:
                normalized = NormalizedVulnerability(
                    title=title,
                    description=description,
                    primary_severity=primary_severity,
                    cvss_score=cvss_score,
                    cvss_version=cvss_version,
                    cvss_vector=cvss_vector,
                    is_cisa_kev=cisa_res.is_listed,
                    cisa_required_action=cisa_res.required_action,
                    cisa_due_date=cisa_res.due_date,
                    epss_probability=epss_res.probability,
                    epss_percentile=epss_res.percentile,
                    affected_cpe_count=len(nvd_res.cpe_configurations),
                )

            return VulnerabilityResponse(
                cve_id=normalized_cve,
                status=overall_status,
                retrieved_at=now,
                normalized=normalized,
                provenance=provenance,
                errors=errors,
            )

        finally:
            if should_close:
                await client.aclose()


aggregator = VulnerabilityAggregator()
