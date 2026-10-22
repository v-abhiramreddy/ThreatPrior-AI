import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.history_store import history_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/history", tags=["Analysis History Audit Trail"])


class UpdateMitigationRequest(BaseModel):
    mitigation_status: str = Field(..., min_length=1, max_length=100)


@router.get("")
async def get_analysis_history(
    search: Optional[str] = Query(None, description="Search term for CVE, title, or analyst"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1-P4 or Critical/High/etc.)"),
    cisa_kev: Optional[str] = Query(None, description="Filter by CISA KEV status (YES/NO/ALL)"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Retrieve durable history of completed vulnerability analyses and audit records."""
    return history_store.list_history(
        search=search,
        priority=priority,
        cisa_kev=cisa_kev,
        limit=limit,
        offset=offset,
    )


@router.get("/{id_or_cve}")
async def get_history_record(id_or_cve: str):
    """Retrieve full stored vulnerability triage analysis without re-running models."""
    record = history_store.get_history_item(id_or_cve)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis history record '{id_or_cve}' not found in audit store.",
        )
    return record


@router.patch("/{id_or_cve}/mitigation")
async def update_record_mitigation(id_or_cve: str, req: UpdateMitigationRequest):
    """Update operational mitigation status for an existing analysis record."""
    success = history_store.update_mitigation_status(id_or_cve, req.mitigation_status)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis history record '{id_or_cve}' not found to update.",
        )
    return {"status": "updated", "id_or_cve": id_or_cve, "mitigation_status": req.mitigation_status}
