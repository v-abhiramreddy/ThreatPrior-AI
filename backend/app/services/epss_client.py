import logging
from datetime import datetime, timezone
from typing import Optional
import httpx

from app.config import settings
from app.models.enums import SourceStatus
from app.models.schemas import EpssProvenance

logger = logging.getLogger(__name__)


class EpssClient:
    """Client for FIRST.org Exploit Prediction Scoring System (EPSS) API."""

    def __init__(self, base_url: Optional[str] = None, timeout: Optional[float] = None):
        self.base_url = base_url or settings.epss_api_url
        self.timeout = timeout or settings.epss_timeout_seconds

    async def get_epss_data(
        self, cve_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> EpssProvenance:
        """Fetch empirical EPSS probability and percentile for a given CVE."""
        retrieval_time = datetime.now(timezone.utc)
        normalized_cve = cve_id.strip().upper()

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout)
            should_close = True

        try:
            params = {"cve": normalized_cve}
            response = await client.get(self.base_url, params=params)

            if response.status_code == 404:
                return EpssProvenance(
                    retrieved_at=retrieval_time,
                    status=SourceStatus.NOT_FOUND,
                    error_message=f"No EPSS scoring entry found for {normalized_cve}.",
                )

            response.raise_for_status()
            data = response.json()

            results = data.get("data", [])
            if not results:
                return EpssProvenance(
                    retrieved_at=retrieval_time,
                    status=SourceStatus.NOT_FOUND,
                    model_version=data.get("version"),
                    error_message=f"No EPSS scores returned for {normalized_cve}.",
                )

            item = results[0]
            try:
                prob = float(item.get("epss")) if item.get("epss") is not None else None
            except (ValueError, TypeError):
                prob = None

            try:
                percentile = float(item.get("percentile")) if item.get("percentile") is not None else None
            except (ValueError, TypeError):
                percentile = None

            return EpssProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.AVAILABLE,
                model_version=data.get("version"),
                probability=prob,
                percentile=percentile,
                score_date=item.get("date"),
            )

        except httpx.TimeoutException:
            logger.warning("EPSS API request timed out for %s", normalized_cve)
            return EpssProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.TIMEOUT,
                error_message="EPSS API request timed out.",
            )
        except Exception as e:
            logger.error("EPSS API request failed for %s: %s", normalized_cve, str(e))
            return EpssProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.FAILED,
                error_message=f"Failed to query EPSS API: {str(e)}",
            )
        finally:
            if should_close:
                await client.aclose()


epss_client = EpssClient()
