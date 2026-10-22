import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict
import httpx
from fastapi import APIRouter

from app.config import settings
from app.services.cisa_client import cisa_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/telemetry", tags=["Telemetry Synchronization"])


@router.get("/status")
async def get_telemetry_status() -> Dict[str, Any]:
    """Retrieve the current synchronization status and telemetry source metrics."""
    cisa_meta = cisa_client.metadata
    return {
        "status": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "cisa_kev": {
                "status": "healthy" if not cisa_meta.get("is_stale") and not cisa_meta.get("last_error") else (
                    "cached_fallback" if cisa_meta.get("loaded") else "unloaded"
                ),
                "count": cisa_meta.get("count", 0),
                "is_stale": cisa_meta.get("is_stale", False),
                "last_refreshed": cisa_meta.get("last_refreshed"),
                "version": cisa_meta.get("version"),
                "error": cisa_meta.get("last_error"),
            },
            "nvd": {
                "endpoint": settings.nvd_api_base_url,
                "has_api_key": bool(settings.nvd_api_key),
            },
            "epss": {
                "endpoint": settings.epss_api_url,
            },
        },
    }


@router.post("/resync")
async def resync_telemetry() -> Dict[str, Any]:
    """Execute live synchronization across CISA KEV, NVD API 2.0, and FIRST.org EPSS.

    Truthfully reflects per-source status without simulating fake success.
    Safely preserves local cached catalog if upstream CDN blocks cloud host requests.
    """
    synced_at = datetime.now(timezone.utc).isoformat()
    sources_result: Dict[str, Any] = {}

    # 1. Synchronize CISA KEV Catalog (force=True to bypass TTL)
    cisa_t0 = time.perf_counter()
    cisa_success = await cisa_client.ensure_catalog(force=True)
    cisa_latency_ms = round((time.perf_counter() - cisa_t0) * 1000, 2)
    cisa_meta = cisa_client.metadata

    if cisa_success:
        sources_result["cisa_kev"] = {
            "status": "healthy",
            "message": f"Successfully synced {cisa_meta.get('count', 0):,} CVEs from live CISA KEV feed.",
            "count": cisa_meta.get("count", 0),
            "source": "live_feed",
            "latency_ms": cisa_latency_ms,
            "error": None,
        }
    elif cisa_client.is_loaded:
        sources_result["cisa_kev"] = {
            "status": "cached_fallback",
            "message": f"Upstream feed unreachable ({cisa_meta.get('last_error')}); preserved {cisa_meta.get('count', 0):,} cached CVEs.",
            "count": cisa_meta.get("count", 0),
            "source": "bundled_seed_cache",
            "latency_ms": cisa_latency_ms,
            "error": cisa_meta.get("last_error"),
        }
    else:
        sources_result["cisa_kev"] = {
            "status": "failed",
            "message": f"CISA KEV catalog sync failed: {cisa_meta.get('last_error')}",
            "count": 0,
            "source": "none",
            "latency_ms": cisa_latency_ms,
            "error": cisa_meta.get("last_error"),
        }

    # 2. Probe NVD API 2.0 reachability
    nvd_t0 = time.perf_counter()
    nvd_headers = {
        "User-Agent": "ThreatPrior-AI/1.0 (Telemetry-Probe; +https://github.com/v-abhiramreddy/ThreatPrior-AI)",
        "Accept": "application/json",
    }
    if settings.nvd_api_key:
        nvd_headers["apiKey"] = settings.nvd_api_key

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            # Probe a well-known CVE endpoint to check live NVD status
            nvd_probe_url = f"{settings.nvd_api_base_url}?cveId=CVE-2021-44228"
            nvd_resp = await client.get(nvd_probe_url, headers=nvd_headers)
            nvd_latency_ms = round((time.perf_counter() - nvd_t0) * 1000, 2)

            if nvd_resp.status_code == 200:
                sources_result["nvd"] = {
                    "status": "healthy",
                    "message": "NIST NVD REST API 2.0 reachable and responsive.",
                    "latency_ms": nvd_latency_ms,
                    "error": None,
                }
            elif nvd_resp.status_code == 429:
                sources_result["nvd"] = {
                    "status": "rate_limited",
                    "message": "NIST NVD REST API 2.0 rate limit exceeded (429).",
                    "latency_ms": nvd_latency_ms,
                    "error": "Rate limit exceeded (HTTP 429)",
                }
            else:
                sources_result["nvd"] = {
                    "status": "degraded",
                    "message": f"NIST NVD returned HTTP {nvd_resp.status_code}.",
                    "latency_ms": nvd_latency_ms,
                    "error": f"HTTP {nvd_resp.status_code}",
                }
    except Exception as e:
        nvd_latency_ms = round((time.perf_counter() - nvd_t0) * 1000, 2)
        sources_result["nvd"] = {
            "status": "failed",
            "message": f"NIST NVD probe failed: {str(e)}",
            "latency_ms": nvd_latency_ms,
            "error": str(e),
        }

    # 3. Probe FIRST.org EPSS API reachability
    epss_t0 = time.perf_counter()
    epss_headers = {
        "User-Agent": "ThreatPrior-AI/1.0 (Telemetry-Probe)",
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            epss_probe_url = f"{settings.epss_api_url}?cve=CVE-2021-44228"
            epss_resp = await client.get(epss_probe_url, headers=epss_headers)
            epss_latency_ms = round((time.perf_counter() - epss_t0) * 1000, 2)

            if epss_resp.status_code == 200:
                sources_result["epss"] = {
                    "status": "healthy",
                    "message": "FIRST.org EPSS API v3 reachable and responsive.",
                    "latency_ms": epss_latency_ms,
                    "error": None,
                }
            else:
                sources_result["epss"] = {
                    "status": "degraded",
                    "message": f"FIRST.org EPSS API returned HTTP {epss_resp.status_code}.",
                    "latency_ms": epss_latency_ms,
                    "error": f"HTTP {epss_resp.status_code}",
                }
    except Exception as e:
        epss_latency_ms = round((time.perf_counter() - epss_t0) * 1000, 2)
        sources_result["epss"] = {
            "status": "failed",
            "message": f"FIRST.org EPSS API probe failed: {str(e)}",
            "latency_ms": epss_latency_ms,
            "error": str(e),
        }

    # Determine overall status
    statuses = [s["status"] for s in sources_result.values()]
    if all(s == "healthy" for s in statuses):
        overall_status = "success"
    elif any(s in ("healthy", "cached_fallback") for s in statuses):
        overall_status = "partial"
    else:
        overall_status = "failed"

    return {
        "status": overall_status,
        "synced_at": synced_at,
        "sources": sources_result,
    }
