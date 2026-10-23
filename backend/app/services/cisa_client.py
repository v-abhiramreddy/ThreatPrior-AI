import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
import httpx

from app.config import settings
from app.models.enums import SourceStatus
from app.models.schemas import CisaKevProvenance

logger = logging.getLogger(__name__)


DEFAULT_CISA_HEADERS = {
    "User-Agent": "ThreatPrior-AI/1.0 (Vulnerability-Triage-Engine; +https://github.com/v-abhiramreddy/ThreatPrior-AI)",
    "Accept": "application/json, text/plain, */*",
}


class CisaKevClient:
    """Client for CISA Known Exploited Vulnerabilities Catalog with in-memory caching."""

    def __init__(self):
        self._catalog_cache: Dict[str, Dict[str, Any]] = {}
        self._catalog_metadata: Dict[str, Any] = {}
        self._last_refreshed: Optional[datetime] = None
        self._last_refresh_error: Optional[str] = None
        self._last_refresh_status: Optional[SourceStatus] = None
        self._lock = asyncio.Lock()

    @property
    def is_loaded(self) -> bool:
        return bool(self._catalog_cache)

    @property
    def count(self) -> int:
        return len(self._catalog_cache)

    @property
    def metadata(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        is_stale = bool(
            self._last_refreshed
            and (now - self._last_refreshed) >= timedelta(hours=settings.cisa_cache_ttl_hours)
        )
        return {
            "loaded": self.is_loaded,
            "count": self.count,
            "version": self._catalog_metadata.get("catalogVersion"),
            "date_released": self._catalog_metadata.get("dateReleased"),
            "last_refreshed": self._last_refreshed.isoformat() if self._last_refreshed else None,
            "is_stale": is_stale,
            "last_error": self._last_refresh_error,
        }

    def load_seed_catalog(self, seed_path: Optional[Path] = None) -> bool:
        """Load bundled seed catalog snapshot from disk on cold start.

        Populates catalog cache immediately so the service has baseline KEV entries
        even if upstream live refresh is blocked by CDN/hosting IP restrictions (e.g. HTTP 403).
        Preserves stale flag until a live refresh succeeds.
        """
        target = seed_path
        if target is None:
            configured = getattr(settings, "cisa_seed_file", None)
            if configured:
                target = Path(configured)
            if not target or not target.is_file():
                target = Path(__file__).resolve().parent.parent / "data" / "cisa_kev_seed.json"

        if not target.is_file():
            logger.info("No CISA KEV seed snapshot file found at %s", target)
            return False

        try:
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)

            new_cache: Dict[str, Dict[str, Any]] = {}
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cveID", "").strip().upper()
                if cve_id:
                    new_cache[cve_id] = item

            if new_cache:
                self._catalog_cache = new_cache
                self._catalog_metadata = {
                    "catalogVersion": data.get("catalogVersion", "seed-snapshot"),
                    "dateReleased": data.get("dateReleased"),
                    "count": data.get("count", len(new_cache)),
                    "is_seed": True,
                }
                # Epoch timestamp ensures cache is considered stale until live fetch succeeds
                self._last_refreshed = datetime(2020, 1, 1, tzinfo=timezone.utc)
                self._last_refresh_error = "Initial catalog loaded from bundled seed snapshot; awaiting live upstream refresh."
                self._last_refresh_status = SourceStatus.FAILED
                logger.info(
                    "Loaded %d entries from CISA KEV seed snapshot (%s)",
                    len(new_cache),
                    target,
                )
                return True
        except Exception as e:
            logger.warning("Failed to load CISA KEV seed snapshot from %s: %s", target, str(e))
        return False

    async def ensure_catalog(self, client: Optional[httpx.AsyncClient] = None, force: bool = False) -> bool:
        """Ensure the CISA KEV catalog is populated and refreshed within the TTL window.
        If force=True, forces an upstream fetch regardless of TTL.
        Returns True if fresh catalog is available, or False if upstream fetch failed.
        """
        now = datetime.now(timezone.utc)
        if not force and (
            self._last_refreshed
            and (now - self._last_refreshed) < timedelta(hours=settings.cisa_cache_ttl_hours)
            and self._catalog_cache
            and not self._last_refresh_error
        ):
            return True

        async with self._lock:
            # Double-check inside lock
            if not force and (
                self._last_refreshed
                and (now - self._last_refreshed) < timedelta(hours=settings.cisa_cache_ttl_hours)
                and self._catalog_cache
                and not self._last_refresh_error
            ):
                return True

            should_close = False
            if client is None:
                client = httpx.AsyncClient(
                    timeout=settings.cisa_timeout_seconds,
                    headers=DEFAULT_CISA_HEADERS,
                )
                should_close = True

            try:
                logger.info("Fetching CISA KEV catalog from %s", settings.cisa_kev_url)
                response = await client.get(settings.cisa_kev_url, headers=DEFAULT_CISA_HEADERS)
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
                self._last_refresh_error = None
                self._last_refresh_status = None
                logger.info("Loaded %d CVE entries from CISA KEV catalog", len(new_cache))
                return True

            except httpx.TimeoutException as e:
                err_msg = f"CISA KEV query timed out after {settings.cisa_timeout_seconds}s"
                logger.warning(err_msg)
                self._last_refresh_error = err_msg
                self._last_refresh_status = SourceStatus.TIMEOUT
                return False
            except httpx.HTTPStatusError as e:
                err_msg = f"CISA KEV HTTP {e.response.status_code}: {e.response.reason_phrase or 'Upstream error'}"
                logger.warning(err_msg)
                self._last_refresh_error = err_msg
                if e.response.status_code == 429:
                    self._last_refresh_status = SourceStatus.RATE_LIMITED
                else:
                    self._last_refresh_status = SourceStatus.FAILED
                return False
            except Exception as e:
                err_msg = f"Failed to fetch/refresh CISA KEV catalog: {str(e)}"
                logger.error(err_msg)
                self._last_refresh_error = err_msg
                self._last_refresh_status = SourceStatus.FAILED
                return False
            finally:
                if should_close:
                    await client.aclose()

    async def get_cve_kev_data(
        self, cve_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> CisaKevProvenance:
        """Query CISA KEV status for a given CVE ID."""
        retrieval_time = datetime.now(timezone.utc)
        normalized_cve = cve_id.strip().upper()

        catalog_fresh = await self.ensure_catalog(client=client)

        # 1. No cache available at all and refresh failed
        if not self._catalog_cache:
            status = self._last_refresh_status or SourceStatus.FAILED
            err = self._last_refresh_error or "CISA KEV catalog unavailable."
            return CisaKevProvenance(
                retrieved_at=retrieval_time,
                status=status,
                is_listed=False,
                notes="Unable to query CISA KEV catalog due to an upstream fetch failure. Absence of listing cannot be determined.",
                error_message=err,
            )

        entry = self._catalog_cache.get(normalized_cve)
        catalog_version = self._catalog_metadata.get("catalogVersion")

        # 2. CVE found in cache (whether fresh or preserved from earlier successful fetch)
        if entry:
            notes = "Confirmed listed in CISA Known Exploited Vulnerabilities catalog."
            err_msg = None
            is_cached = not catalog_fresh or bool(self._last_refresh_error)
            if is_cached and self._last_refresh_error:
                err_msg = f"Upstream refresh failed: {self._last_refresh_error}. Data served from cached catalog."
                notes = (
                    f"Confirmed listed in cached CISA KEV catalog (catalog version: {catalog_version}, "
                    f"cached at {self._last_refreshed.isoformat() if self._last_refreshed else 'unknown'}). "
                    f"Note: upstream refresh failed."
                )

            last_valid_refresh = self._last_refreshed if self._last_refreshed and self._last_refreshed.year > 2021 else None
            return CisaKevProvenance(
                retrieved_at=retrieval_time,
                status=SourceStatus.LISTED,
                catalog_version=catalog_version,
                catalog_date_released=self._catalog_metadata.get("dateReleased"),
                last_refreshed_at=last_valid_refresh,
                is_cached=is_cached,
                is_listed=True,
                date_added=entry.get("dateAdded"),
                vendor_project=entry.get("vendorProject"),
                product=entry.get("product"),
                vulnerability_name=entry.get("vulnerabilityName"),
                due_date=entry.get("dueDate"),
                required_action=entry.get("requiredAction"),
                known_ransomware_campaign_use=entry.get("knownRansomwareCampaignUse"),
                notes=notes,
                error_message=err_msg,
            )

        # 3. CVE NOT found in cache
        # CRITICAL SAFETY INVARIANT: If the catalog is stale or refresh failed, absence is NOT proof of non-listing!
        if not catalog_fresh or self._last_refresh_error:
            status = self._last_refresh_status or SourceStatus.FAILED
            refreshed_str = self._last_refreshed.isoformat() if self._last_refreshed else "unknown"
            err_detail = self._last_refresh_error or "Catalog cache is stale and could not be refreshed."
            last_valid_refresh = self._last_refreshed if self._last_refreshed and self._last_refreshed.year > 2021 else None
            return CisaKevProvenance(
                retrieved_at=retrieval_time,
                status=status,
                catalog_version=catalog_version,
                catalog_date_released=self._catalog_metadata.get("dateReleased"),
                last_refreshed_at=last_valid_refresh,
                is_cached=True,
                is_listed=False,
                notes=(
                    f"Vulnerability not found in cached CISA KEV catalog, but cache is stale (last refreshed: {refreshed_str}) "
                    f"and upstream refresh failed ({err_detail}). Absence from KEV catalog cannot be confirmed."
                ),
                error_message=(
                    f"CISA KEV catalog cache is stale (last refreshed {refreshed_str}) and upstream refresh failed: {err_detail}. "
                    "Absence cannot be verified."
                ),
            )

        # 4. Fresh catalog confirmed absence
        return CisaKevProvenance(
            retrieved_at=retrieval_time,
            status=SourceStatus.NOT_LISTED,
            catalog_version=catalog_version,
            catalog_date_released=self._catalog_metadata.get("dateReleased"),
            last_refreshed_at=self._last_refreshed,
            is_cached=False,
            is_listed=False,
            notes=(
                "Not listed in CISA KEV catalog. Absence from this catalog indicates only that "
                "CISA has not confirmed in-wild exploitation for this entry; it does not indicate "
                "absence of risk or proof of safety."
            ),
        )


cisa_client = CisaKevClient()
