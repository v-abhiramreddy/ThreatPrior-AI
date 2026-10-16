import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import httpx

from app.config import settings
from app.models.enums import SourceStatus, SeverityLevel
from app.models.schemas import NvdProvenance, CvssMetrics

logger = logging.getLogger(__name__)


class NvdClient:
    """Client for NIST National Vulnerability Database (NVD) API 2.0."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.base_url = base_url or settings.nvd_api_base_url
        self.api_key = api_key or settings.nvd_api_key
        self.timeout = timeout or settings.nvd_timeout_seconds

    def _get_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "ThreatPriorAI/0.2.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _parse_cvss_metric(self, metric_list: List[Dict[str, Any]]) -> Optional[CvssMetrics]:
        if not metric_list:
            return None

        # Prioritize Primary entry if available, else first
        selected = metric_list[0]
        for item in metric_list:
            if item.get("type", "").lower() == "primary":
                selected = item
                break

        cvss_data = selected.get("cvssData", {})
        try:
            base_score = float(cvss_data.get("baseScore", 0.0))
        except (ValueError, TypeError):
            return None

        vector_string = cvss_data.get("vectorString", "")
        raw_severity = (cvss_data.get("baseSeverity") or selected.get("baseSeverity") or "").upper()

        severity_map = {
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
        }
        severity = severity_map.get(raw_severity, SeverityLevel.UNKNOWN)

        exploitability = selected.get("exploitabilityScore")
        impact = selected.get("impactScore")

        return CvssMetrics(
            base_score=base_score,
            severity=severity,
            vector_string=vector_string,
            exploitability_score=float(exploitability) if exploitability is not None else None,
            impact_score=float(impact) if impact is not None else None,
        )

    async def get_cve_data(
        self, cve_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> NvdProvenance:
        """Fetch and parse vulnerability record from NVD API 2.0 with bounded retries."""
        retrieval_time = datetime.now(timezone.utc)
        normalized_cve = cve_id.strip().upper()

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout)
            should_close = True

        attempt = 0
        max_retries = settings.max_retries

        try:
            while attempt <= max_retries:
                attempt += 1
                try:
                    params = {"cveId": normalized_cve}
                    response = await client.get(
                        self.base_url,
                        params=params,
                        headers=self._get_headers(),
                    )

                    if response.status_code == 404:
                        return NvdProvenance(
                            retrieved_at=retrieval_time,
                            status=SourceStatus.NOT_FOUND,
                            error_message=f"No record found in NVD for {normalized_cve}.",
                        )

                    if response.status_code == 429:
                        logger.warning("NVD rate limit encountered (attempt %d/%d)", attempt, max_retries + 1)
                        if attempt <= max_retries:
                            retry_after = response.headers.get("Retry-After")
                            wait_time = float(retry_after) if retry_after and retry_after.isdigit() else (settings.retry_backoff_factor ** attempt)
                            wait_time = min(wait_time, 10.0)  # Bound retry delay
                            await asyncio.sleep(wait_time)
                            continue
                        else:
                            return NvdProvenance(
                                retrieved_at=retrieval_time,
                                status=SourceStatus.RATE_LIMITED,
                                error_message="NVD API rate limit exceeded (HTTP 429). Upstream request throttled.",
                            )

                    if response.status_code in (502, 503, 504) and attempt <= max_retries:
                        await asyncio.sleep(settings.retry_backoff_factor ** attempt)
                        continue

                    response.raise_for_status()
                    data = response.json()

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities or data.get("totalResults", 0) == 0:
                        return NvdProvenance(
                            retrieved_at=retrieval_time,
                            status=SourceStatus.NOT_FOUND,
                            error_message=f"NVD query returned 0 results for {normalized_cve}.",
                        )

                    cve_record = vulnerabilities[0].get("cve", {})

                    # Extract primary English description
                    descriptions = cve_record.get("descriptions", [])
                    primary_desc = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            primary_desc = d.get("value", "")
                            break
                    if not primary_desc and descriptions:
                        primary_desc = descriptions[0].get("value", "")

                    # Extract metrics
                    metrics_obj = cve_record.get("metrics", {})
                    cvss_v31 = self._parse_cvss_metric(metrics_obj.get("cvssMetricV31", []))
                    cvss_v30 = self._parse_cvss_metric(metrics_obj.get("cvssMetricV30", []))
                    cvss_v20 = self._parse_cvss_metric(metrics_obj.get("cvssMetricV2", []))

                    # Extract CWE weaknesses
                    weaknesses: List[str] = []
                    for w in cve_record.get("weaknesses", []):
                        for desc_item in w.get("description", []):
                            val = desc_item.get("value")
                            if val and val not in weaknesses:
                                weaknesses.append(val)

                    # Extract affected CPEs
                    cpes: List[str] = []
                    for conf in cve_record.get("configurations", []):
                        for node in conf.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                criteria = match.get("criteria")
                                if criteria and criteria not in cpes:
                                    cpes.append(criteria)

                    return NvdProvenance(
                        retrieved_at=retrieval_time,
                        status=SourceStatus.AVAILABLE,
                        vuln_status=cve_record.get("vulnStatus"),
                        published_date=cve_record.get("published"),
                        last_modified_date=cve_record.get("lastModified"),
                        description=primary_desc,
                        cvss_v31=cvss_v31,
                        cvss_v30=cvss_v30,
                        cvss_v20=cvss_v20,
                        weaknesses=weaknesses,
                        cpe_configurations=cpes,
                    )

                except httpx.TimeoutException:
                    if attempt <= max_retries:
                        await asyncio.sleep(settings.retry_backoff_factor ** attempt)
                        continue
                    logger.warning("NVD API timed out for %s", normalized_cve)
                    return NvdProvenance(
                        retrieved_at=retrieval_time,
                        status=SourceStatus.TIMEOUT,
                        error_message="NVD API request timed out.",
                    )
                except httpx.HTTPStatusError as e:
                    logger.error("NVD API HTTP error: %s", str(e))
                    return NvdProvenance(
                        retrieved_at=retrieval_time,
                        status=SourceStatus.FAILED,
                        error_message=f"NVD API returned error: HTTP {e.response.status_code}",
                    )

        except Exception as e:
            logger.error("Unexpected error querying NVD for %s: %s", normalized_cve, str(e))
            return NvdProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.FAILED,
                error_message=f"NVD query failed: {str(e)}",
            )
        finally:
            if should_close:
                await client.aclose()


nvd_client = NvdClient()
