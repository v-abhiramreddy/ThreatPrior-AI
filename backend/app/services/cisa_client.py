import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import httpx

from app.config import settings
from app.models.enums import SourceStatus
from app.models.schemas import CisaKevProvenance

logger = logging.getLogger(__name__)


class CisaKevClient:
    """Client for CISA Known Exploited Vulnerabilities Catalog with in-memory caching."""

    def __init__(self):
        self._catalog_cache: Dict[str, Dict[str, Any]] = {}
        self._catalog_metadata: Dict[str, Any] = {}
        self._last_refreshed: Optional[datetime] = None
        self._lock = asyncio.Lock()

    @property
    def is_loaded(self) -> bool:
        return bool(self._catalog_cache)

    @property
    def count(self) -> int:
        return len(self._catalog_cache)

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "loaded": self.is_loaded,
            "count": self.count,
            "version": self._catalog_metadata.get("catalogVersion"),
            "date_released": self._catalog_metadata.get("dateReleased"),
            "last_refreshed": self._last_refreshed.isoformat() if self._last_refreshed else None,
        }

    async def ensure_catalog(self, client: Optional[httpx.AsyncClient] = None) -> bool:
        """Ensure the CISA KEV catalog is populated and refreshed within the TTL window."""
        now = datetime.now(timezone.utc)
        if (
            self._last_refreshed
            and (now - self._last_refreshed) < timedelta(hours=settings.cisa_cache_ttl_hours)
            and self._catalog_cache
        ):
            return True

        async with self._lock:
            # Double-check inside lock
            if (
                self._last_refreshed
                and (now - self._last_refreshed) < timedelta(hours=settings.cisa_cache_ttl_hours)
                and self._catalog_cache
            ):
                return True

            try:
                should_close = False
                if client is None:
                    client = httpx.AsyncClient(timeout=settings.cisa_timeout_seconds)
                    should_close = True

                try:
                    logger.info("Fetching CISA KEV catalog from %s", settings.cisa_kev_url)
                    response = await client.get(settings.cisa_kev_url)
                    response.raise_for_status()
                    data = response.json()

                    new_cache: Dict[str, Dict[str, Any]] = {}
                    for item in data.get("vulnerabilities", []):
                        cve_id = item.get("cveID", "").strip().upper()
                        if cve_id:
                            new_cache[cve_id] = item

                    self._catalog_cache = new_cache
                    self._catalog_metadata = {
                        "catalogVersion": data.get("catalogVersion"),
                        "dateReleased": data.get("dateReleased"),
                        "count": data.get("count", len(new_cache)),
                    }
                    self._last_refreshed = datetime.now(timezone.utc)
                    logger.info("Loaded %d CVE entries from CISA KEV catalog", len(new_cache))
                    return True
                finally:
                    if should_close:
                        await client.aclose()

            except Exception as e:
                logger.error("Failed to fetch/refresh CISA KEV catalog: %s", str(e))
                # Retain existing cache if available
                return bool(self._catalog_cache)

    async def get_cve_kev_data(
        self, cve_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> CisaKevProvenance:
        """Query CISA KEV status for a given CVE ID."""
        retrieval_time = datetime.now(timezone.utc)
        normalized_cve = cve_id.strip().upper()

        catalog_ready = await self.ensure_catalog(client=client)
        if not catalog_ready:
            return CisaKevProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.FAILED,
                is_listed=False,
                notes="Unable to query CISA KEV catalog due to an upstream fetch failure.",
                error_message="CISA KEV catalog unavailable.",
            )

        entry = self._catalog_cache.get(normalized_cve)
        catalog_version = self._catalog_metadata.get("catalogVersion")

        if entry:
            return CisaKevProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.LISTED,
                catalog_version=catalog_version,
                is_listed=True,
                date_added=entry.get("dateAdded"),
                vendor_project=entry.get("vendorProject"),
                product=entry.get("product"),
                vulnerability_name=entry.get("vulnerabilityName"),
                due_date=entry.get("dueDate"),
                required_action=entry.get("requiredAction"),
                known_ransomware_campaign_use=entry.get("knownRansomwareCampaignUse"),
                notes="Confirmed listed in CISA Known Exploited Vulnerabilities catalog.",
            )
        else:
            return CisaKevProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.NOT_LISTED,
                catalog_version=catalog_version,
                is_listed=False,
                notes=(
                    "Not listed in CISA KEV catalog. Absence from this catalog indicates only that "
                    "CISA has not confirmed in-wild exploitation for this entry; it does not indicate "
                    "absence of risk or proof of safety."
                ),
            )


cisa_client = CisaKevClient()
