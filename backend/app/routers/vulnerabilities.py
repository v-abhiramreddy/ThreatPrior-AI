import re
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from app.models.enums import OverallStatus
from app.models.schemas import VulnerabilityResponse
from app.services.aggregator import aggregator

router = APIRouter(prefix="/api", tags=["Vulnerabilities"])

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@router.get(
    "/vulnerabilities/{cve_id}",
    response_model=VulnerabilityResponse,
    responses={
        400: {"description": "Invalid CVE Identifier Format"},
        404: {"description": "Vulnerability Not Found Across All Sources"},
    },
)
async def get_vulnerability(cve_id: str):
    """Retrieve normalized threat intelligence across NVD, CISA KEV, and EPSS."""
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

    response = await aggregator.aggregate_cve(normalized_cve)

    if response.status == OverallStatus.NOT_FOUND:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=response.model_dump(mode="json"),
        )

    if response.status == OverallStatus.ERROR and response.normalized is None:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content=response.model_dump(mode="json"),
        )

    return response
