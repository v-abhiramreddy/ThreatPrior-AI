from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings
from app.models.schemas import HealthResponse
from app.services.cisa_client import cisa_client

router = APIRouter(prefix="/api", tags=["System"])


@router.get("/health", response_model=HealthResponse)
async def get_health():
    """Health check endpoint providing service and upstream catalog cache status."""
    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        version=settings.app_version,
        timestamp=datetime.now(timezone.utc),
        cisa_catalog=cisa_client.metadata,
    )
