from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.enums import SourceStatus, OverallStatus, SeverityLevel


class CvssMetrics(BaseModel):
    base_score: float = Field(..., description="CVSS base numerical score (0.0 - 10.0)")
    severity: SeverityLevel = Field(..., description="CVSS qualitative severity rating")
    vector_string: str = Field(..., description="CVSS vector string specification")
    exploitability_score: Optional[float] = Field(default=None)
    impact_score: Optional[float] = Field(default=None)


class NvdProvenance(BaseModel):
    source: str = Field(default="NIST National Vulnerability Database API v2.0")
    retrieved_at: Optional[datetime] = None
    status: SourceStatus
    vuln_status: Optional[str] = None
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    description: Optional[str] = None
    cvss_v31: Optional[CvssMetrics] = None
    cvss_v30: Optional[CvssMetrics] = None
    cvss_v20: Optional[CvssMetrics] = None
    weaknesses: List[str] = Field(default_factory=list)
    cpe_configurations: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None


class CisaKevProvenance(BaseModel):
    source: str = Field(default="CISA Known Exploited Vulnerabilities Catalog")
    retrieved_at: Optional[datetime] = None
    status: SourceStatus
    catalog_version: Optional[str] = None
    is_listed: bool = Field(default=False)
    date_added: Optional[str] = None
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    due_date: Optional[str] = None
    required_action: Optional[str] = None
    known_ransomware_campaign_use: Optional[str] = None
    notes: str = Field(
        ...,
        description="Explicit provenance note describing catalog presence or absence.",
    )
    error_message: Optional[str] = None


class EpssProvenance(BaseModel):
    source: str = Field(default="FIRST.org EPSS API v3")
    retrieved_at: Optional[datetime] = None
    status: SourceStatus
    model_version: Optional[str] = None
    probability: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Estimated probability of exploitation activity in next 30 days",
    )
    percentile: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Empirical percentile ranking relative to all scored CVEs",
    )
    score_date: Optional[str] = None
    interpretive_note: str = Field(
        default="Estimated probability of active exploitation in next 30 days based on observed threat telemetry. Not a confirmation of exploitation or severity."
    )
    error_message: Optional[str] = None


class Provenance(BaseModel):
    nvd: NvdProvenance
    cisa_kev: CisaKevProvenance
    epss: EpssProvenance


class NormalizedVulnerability(BaseModel):
    title: str = Field(..., description="Vulnerability headline or identifier title")
    description: str = Field(..., description="Authoritative summary description")
    primary_severity: SeverityLevel = Field(..., description="Normalized primary severity rating")
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    is_cisa_kev: bool = False
    cisa_required_action: Optional[str] = None
    cisa_due_date: Optional[str] = None
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    affected_cpe_count: int = 0


class VulnerabilityResponse(BaseModel):
    cve_id: str = Field(..., description="Common Vulnerabilities and Exposures Identifier")
    status: OverallStatus = Field(..., description="Overall aggregation status")
    retrieved_at: datetime = Field(..., description="UTC timestamp of response synthesis")
    normalized: Optional[NormalizedVulnerability] = None
    provenance: Provenance
    errors: List[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str = "healthy"
    service: str
    version: str
    timestamp: datetime
    cisa_catalog: dict
