import re
import logging
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from app.models.enums import OverallStatus
from app.models.triage import TriageResponse, DecisionEngineType
from app.services.aggregator import aggregator
from app.services.decision_engine import decision_engine, DecisionEngineError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Triage Decision Engine"])

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@router.get(
    "/vulnerabilities/{cve_id}/triage",
    response_model=TriageResponse,
    responses={
        400: {"description": "Invalid CVE Identifier Format"},
        404: {"description": "Vulnerability Not Found Across All Sources"},
        503: {"description": "AI Decision Engine Unavailable (when fallback disabled)"},
    },
)
async def triage_vulnerability(cve_id: str):
    """Retrieve normalized threat intelligence and evaluate it through the

    Strands Decider 2B + Amazon Bedrock AI decision layer.
    """
    normalized_cve = cve_id.strip().upper()

    # Pre-flight syntax validation before issuing external requests
    if not CVE_REGEX.match(normalized_cve):
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

    return TriageResponse(
        cve_id=normalized_cve,
        status=vuln_response.status,
        retrieved_at=vuln_response.retrieved_at,
        decision=decision,
        risk_validation=decision.risk_validation,
        normalized=vuln_response.normalized,
        provenance=vuln_response.provenance,
        errors=vuln_response.errors,
    )
