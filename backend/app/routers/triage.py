import logging
import re
import time
from collections import defaultdict
from threading import Lock
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.models.enums import OverallStatus, SourceStatus
from app.models.triage import DecisionEngineType, TriageResponse
from app.services.aggregator import aggregator
from app.services.decision_engine import DecisionEngineError, decision_engine
from app.services.history_store import history_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Triage Decision Engine"])

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class InMemoryRateLimiter:
    """Sliding-window in-memory rate limiter per IP address with automatic memory pruning."""

    def __init__(self, max_tracked_ips: int = 1000):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._max_tracked_ips = max_tracked_ips

    def check(self, client_ip: str, limit_per_minute: int) -> None:
        if limit_per_minute <= 0:
            return

        now = time.time()
        window_start = now - 60.0

        with self._lock:
            # Defensive memory protection: prune expired IPs when tracking table grows large
            if len(self._requests) > self._max_tracked_ips:
                stale_ips = [ip for ip, reqs in self._requests.items() if not reqs or reqs[-1] <= window_start]
                for ip in stale_ips:
                    del self._requests[ip]

            # Prune timestamps outside the 60s sliding window
            timestamps = [t for t in self._requests[client_ip] if t > window_start]
            if len(timestamps) >= limit_per_minute:
                retry_after = int(max(1, 60.0 - (now - timestamps[0])))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded: maximum {limit_per_minute} triage requests per minute per IP.",
                    headers={"Retry-After": str(retry_after)},
                )
            timestamps.append(now)
            self._requests[client_ip] = timestamps

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()


triage_rate_limiter = InMemoryRateLimiter()


def rate_limit_triage(request: Request) -> None:
    client_ip = "127.0.0.1"
    # Prioritize client IP from reverse-proxy header when running behind Blitz/Render/ALB
    if "x-forwarded-for" in request.headers:
        forwarded = request.headers["x-forwarded-for"].split(",")[0].strip()
        if forwarded:
            client_ip = forwarded
    elif request.client and request.client.host:
        client_ip = request.client.host

    limit = getattr(settings, "triage_rate_limit_per_minute", 60)
    triage_rate_limiter.check(client_ip, limit)


@router.get(
    "/vulnerabilities/{cve_id}/triage",
    response_model=TriageResponse,
    dependencies=[Depends(rate_limit_triage)],
    responses={
        400: {"description": "Invalid CVE Identifier Format"},
        404: {"description": "Vulnerability Not Found Across All Sources"},
        429: {"description": "Rate Limit Exceeded for AI Triage"},
        503: {"description": "AI Decision Engine Unavailable (when fallback disabled)"},
    },
)
async def triage_vulnerability(cve_id: str):
    """Retrieve normalized threat intelligence and evaluate it through the

    Strands Decider 2B + Amazon Bedrock AI decision layer.
    """
    normalized_cve = cve_id.strip().upper()

    # Pre-flight syntax and length validation before issuing external requests
    if len(normalized_cve) > 30 or not CVE_REGEX.match(normalized_cve):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid CVE identifier '{cve_id}'. Format must strictly follow "
                "CVE-YYYY-NNNNN (e.g. CVE-2021-44228)."
            ),
        )

    # 1. Reuse existing aggregator pipeline (zero duplicate requests)
    vuln_response = await aggregator.aggregate_cve(normalized_cve)

    if vuln_response.status == OverallStatus.NOT_FOUND:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "cve_id": normalized_cve,
                "status": OverallStatus.NOT_FOUND.value,
                "detail": f"Vulnerability {normalized_cve} not found in NVD, CISA KEV, or EPSS.",
                "errors": vuln_response.errors,
            },
        )

    # If normalized is None, evidence is insufficient to evaluate risk or confirm absence
    if vuln_response.normalized is None:
        nvd_stat = vuln_response.provenance.nvd.status
        epss_stat = vuln_response.provenance.epss.status
        cisa_stat = vuln_response.provenance.cisa_kev.status
        if (
            nvd_stat == SourceStatus.NOT_FOUND
            and epss_stat == SourceStatus.NOT_FOUND
            and cisa_stat in (SourceStatus.FAILED, SourceStatus.TIMEOUT, SourceStatus.RATE_LIMITED)
        ):
            detail_msg = (
                f"Insufficient evidence to triage {normalized_cve}: No record found in NVD or EPSS, "
                "but CISA KEV check failed. Cannot confirm absence or evaluate risk."
            )
        else:
            detail_msg = (
                f"Insufficient vulnerability evidence to triage {normalized_cve}: Upstream intelligence sources unavailable."
            )

        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "cve_id": normalized_cve,
                "status": vuln_response.status.value,
                "detail": detail_msg,
                "engine": DecisionEngineType.UNAVAILABLE.value,
                "provenance": vuln_response.provenance.model_dump(mode="json"),
                "errors": vuln_response.errors,
            },
        )

    # 2. Evaluate through decision engine (Bedrock + Decider, or explicit baseline fallback)
    try:
        decision = await decision_engine.evaluate_vulnerability(vuln_response)
    except DecisionEngineError as e:
        logger.error("AI decision engine failed with fallback disabled: %s", e.message)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "cve_id": normalized_cve,
                "status": vuln_response.status.value,
                "detail": e.message,
                "engine": DecisionEngineType.UNAVAILABLE.value,
                "errors": vuln_response.errors + [e.message],
            },
        )

    triage_result = TriageResponse(
        cve_id=normalized_cve,
        status=vuln_response.status,
        retrieved_at=vuln_response.retrieved_at,
        decision=decision,
        risk_validation=decision.risk_validation,
        normalized=vuln_response.normalized,
        provenance=vuln_response.provenance,
        errors=vuln_response.errors,
    )

    try:
        history_store.save_analysis(triage_result)
    except Exception as e:
        logger.warning("Failed to record triage analysis in history store: %s", str(e))

    return triage_result
