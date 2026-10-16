import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import health, vulnerabilities, triage
from app.services.cisa_client import cisa_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threatprior.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: preload CISA KEV catalog in background
    logger.info("Starting ThreatPrior AI backend service...")
    asyncio.create_task(cisa_client.ensure_catalog())
    yield
    # Shutdown
    logger.info("Shutting down ThreatPrior AI backend service...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Vulnerability Intelligence Backend for ThreatPrior AI (NVD API 2.0, CISA KEV, EPSS)",
    lifespan=lifespan,
)

# CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(vulnerabilities.router)
app.include_router(triage.router)
