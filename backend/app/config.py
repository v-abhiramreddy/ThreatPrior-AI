from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Anchor environment file resolution to the backend directory
BACKEND_DIR = Path(__file__).resolve().parent.parent
BACKEND_ENV_FILE = BACKEND_DIR / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment or .env file."""

    # Upstream API URLs
    nvd_api_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD REST API 2.0 Base URL",
    )
    cisa_kev_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="CISA Known Exploited Vulnerabilities Catalog JSON URL",
    )
    epss_api_url: str = Field(
        default="https://api.first.org/data/v1/epss",
        description="FIRST.org EPSS API URL",
    )

    # API Keys & Credentials
    nvd_api_key: Optional[str] = Field(
        default=None,
        description="Optional NVD API Key for higher rate limits (50 req / 30s)",
    )

    # Timeouts (seconds)
    nvd_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    cisa_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    epss_timeout_seconds: float = Field(default=6.0, ge=1.0, le=30.0)

    # Caching & Retries
    cisa_cache_ttl_hours: int = Field(default=4, ge=1, le=24)
    cisa_seed_file: Optional[str] = Field(
        default=None,
        description="Optional custom path to bundled initial CISA KEV seed snapshot JSON",
    )
    max_retries: int = Field(default=2, ge=0, le=5)
    retry_backoff_factor: float = Field(default=1.5, ge=1.0, le=5.0)

    # AWS Bedrock & Strands Decider Settings
    aws_region: str = Field(
        default="us-east-1",
        description="AWS Region for Amazon Bedrock runtime",
    )
    bedrock_model_id: str = Field(
        default="amazon.nova-lite-v1:0",
        description=(
            "Amazon Bedrock model ID or inference profile for Stage 2 triage reasoning and explanation. "
            "Supports Amazon Nova (e.g., 'amazon.nova-lite-v1:0') and Anthropic Claude "
            "(e.g., 'anthropic.claude-sonnet-4-6', 'us.anthropic.claude-sonnet-4-6', or 'au.anthropic.claude-sonnet-4-6')."
        ),
    )
    strands_decider_model_id: str = Field(
        default="StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
        description="Strands Decider 2B model checkpoint ID",
    )
    strands_decider_url: Optional[str] = Field(
        default="http://127.0.0.1:8080",
        description="Base URL for remote strands-decider HTTP server (POST /v1/systemone)",
    )
    strands_decider_mode: str = Field(
        default="auto",
        description="Strands Decider mode: 'remote' (HTTP server), 'local' (load_engine), or 'auto' (remote with local fallback)",
    )
    strands_decider_device: str = Field(
        default="auto",
        description="Execution device for local Strands Decider: 'auto', 'cpu', 'cuda', etc.",
    )
    strands_decider_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=120.0,
        description="Timeout in seconds for Strands Decider System-1 inference",
    )
    allow_baseline_fallback: bool = Field(
        default=True,
        description="Allow fallback to deterministic baseline if AI engines are unavailable or unauthorized",
    )
    decision_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=120.0,
        description="Timeout for AI decision inference",
    )
    max_decision_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum bounded retries for transient Bedrock throttling or server errors",
    )

    # Model Download & Resource Protection
    allow_local_model_download: bool = Field(
        default=False,
        description="Explicit opt-in required to automatically download multi-gigabyte local model weights into memory.",
    )

    # API Cost & Abuse Protection
    triage_rate_limit_per_minute: int = Field(
        default=60,
        ge=0,
        description="Rate limit for live AI triage requests per client IP per minute (0 to disable).",
    )

    # CORS Settings
    cors_allowed_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        description="Comma-separated allowed origins for cross-origin requests",
    )

    # Service metadata
    app_name: str = "ThreatPrior AI Vulnerability Intelligence Service"
    app_version: str = "0.3.0"
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=BACKEND_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
