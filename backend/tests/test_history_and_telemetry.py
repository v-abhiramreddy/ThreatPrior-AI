import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.main import app
from app.models.enums import OverallStatus, SeverityLevel, SourceStatus
from app.models.schemas import (
    CisaKevProvenance,
    CvssMetrics,
    EpssProvenance,
    NormalizedVulnerability,
    NvdProvenance,
    Provenance,
    VulnerabilityResponse,
)
from app.models.triage import (
    DecisionEngineType,
    ModelInvocationStatus,
    RiskValidationResult,
    RiskValidationStatus,
    TriageDecision,
    TriagePriority,
    TriageResponse,
)
from app.services.history_store import HistoryStore
from datetime import datetime, timezone


def make_dummy_triage_response(
    cve_id: str = "CVE-2021-44228",
    priority: TriagePriority = TriagePriority.CRITICAL,
    engine: DecisionEngineType = DecisionEngineType.DUAL_AI,
    bedrock_status: ModelInvocationStatus = ModelInvocationStatus.SUCCESS,
    decider_status: ModelInvocationStatus = ModelInvocationStatus.SUCCESS,
) -> TriageResponse:
    now = datetime.now(timezone.utc)
    decision = TriageDecision(
        priority=priority,
        rationale="Evidence-based critical priority evaluation.",
        risk_factors=["Active exploitation in CISA KEV"],
        recommended_action="Apply emergency mitigation per directive.",
        confidence=0.96,
        confidence_is_calibrated=False,
        confidence_explanation="High confidence System-1 priority evaluation.",
        evidence_limitations=[],
        engine=engine,
        decider_model_id="strands-decider-2b",
        bedrock_model_id="amazon.nova-lite-v1:0" if bedrock_status == ModelInvocationStatus.SUCCESS else None,
        decider_status=decider_status,
        bedrock_status=bedrock_status,
        decided_at=now,
        risk_validation=RiskValidationResult(
            model_priority=priority,
            evidence_priority=priority,
            risk_validation_status=RiskValidationStatus.ALIGNED,
            risk_factors=["CISA KEV Listed"],
            validation_explanation="Aligned with deterministic policy rules.",
        ),
    )
    return TriageResponse(
        cve_id=cve_id,
        status=OverallStatus.OK,
        retrieved_at=now,
        decision=decision,
        risk_validation=decision.risk_validation,
        normalized=NormalizedVulnerability(
            title=f"Test Advisory for {cve_id}",
            description="Remote code execution vulnerability.",
            primary_severity=SeverityLevel.CRITICAL,
            cvss_score=10.0,
            cvss_version="3.1",
            is_cisa_kev=True,
            epss_probability=0.974,
            epss_percentile=0.998,
            affected_cpe_count=2,
        ),
        provenance=Provenance(
            nvd=NvdProvenance(
                source="NIST NVD",
                status=SourceStatus.AVAILABLE,
                cvss_v31=CvssMetrics(base_score=10.0, severity=SeverityLevel.CRITICAL, vector_string="CVSS:3.1/AV:N"),
            ),
            cisa_kev=CisaKevProvenance(
                source="CISA KEV",
                status=SourceStatus.LISTED,
                is_listed=True,
                required_action="Apply mitigation immediately.",
                notes="Target of Federal Binding Operational Directive 22-01.",
            ),
            epss=EpssProvenance(
                source="FIRST.org EPSS",
                status=SourceStatus.AVAILABLE,
                probability=0.974,
                percentile=0.998,
                score_date="2026-10-20",
                interpretive_note="High probability",
            ),
        ),
    )


def test_history_store_save_and_retrieve():
    """Test saving to SQLite history store and retrieving the record."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_history.db"
        store = HistoryStore(db_path=str(db_path))

        resp = make_dummy_triage_response("CVE-2021-44228", priority=TriagePriority.CRITICAL)
        saved = store.save_analysis(resp)

        assert saved["cve"] == "CVE-2021-44228"
        assert saved["priority"] == "P1"
        assert saved["cisaKev"] == "YES"
        assert saved["engine"] == "dual-ai"
        assert saved["mitigationStatus"] == "Open / Queued"

        # List records
        listing = store.list_history()
        assert listing["total_count"] == 1
        assert listing["critical_count"] == 1
        assert listing["kev_count"] == 1
        assert len(listing["items"]) == 1

        # Retrieve full record
        full = store.get_history_item("CVE-2021-44228")
        assert full is not None
        assert full["summary"]["cve"] == "CVE-2021-44228"
        assert full["triage_response"]["cve_id"] == "CVE-2021-44228"
        assert full["triage_response"]["decision"]["engine"] == "dual-ai"
        store.close()


def test_history_store_preserves_across_restarts():
    """Verify records survive application restart by opening a new connection to the same SQLite file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "restart_test.db"

        # Instance 1: Write record
        store1 = HistoryStore(db_path=str(db_path))
        resp = make_dummy_triage_response("CVE-2023-38606", priority=TriagePriority.HIGH)
        store1.save_analysis(resp)
        store1.close()

        # Instance 2: Simulate cold restart of backend process
        store2 = HistoryStore(db_path=str(db_path))
        listing = store2.list_history()
        assert listing["total_count"] == 1
        assert listing["items"][0]["cve"] == "CVE-2023-38606"
        assert listing["items"][0]["priority"] == "P2"
        store2.close()


def test_history_store_truthful_degraded_status():
    """Verify degraded decider-only analysis is recorded truthfully, never as dual-ai."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "degraded_test.db"
        store = HistoryStore(db_path=str(db_path))

        resp = make_dummy_triage_response(
            "CVE-2024-21413",
            priority=TriagePriority.HIGH,
            engine=DecisionEngineType.DECIDER_ONLY,
            bedrock_status=ModelInvocationStatus.FAILED,
            decider_status=ModelInvocationStatus.SUCCESS,
        )
        store.save_analysis(resp)

        item = store.get_history_item("CVE-2024-21413")
        assert item is not None
        assert item["summary"]["engine"] == "decider-only"
        assert item["summary"]["deciderStatus"] == "success"
        assert item["summary"]["bedrockStatus"] == "failed"
        store.close()


def test_history_store_filtering():
    """Verify search, priority, and KEV filtering in history store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "filter_test.db"
        store = HistoryStore(db_path=str(db_path))

        resp1 = make_dummy_triage_response("CVE-2021-44228", priority=TriagePriority.CRITICAL)
        resp2 = make_dummy_triage_response("CVE-2023-38606", priority=TriagePriority.HIGH)
        store.save_analysis(resp1)
        store.save_analysis(resp2)

        # Filter by priority P1
        p1_list = store.list_history(priority="P1")
        assert p1_list["total_count"] == 1
        assert p1_list["items"][0]["cve"] == "CVE-2021-44228"

        # Search by CVE query
        search_list = store.list_history(search="38606")
        assert search_list["total_count"] == 1
        assert search_list["items"][0]["cve"] == "CVE-2023-38606"
        store.close()


def test_history_api_endpoints():
    """Test /api/history API endpoints using FastAPI TestClient."""
    client = TestClient(app)
    response = client.get("/api/history")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total_count" in data
    assert "queue_count" in data


@pytest.mark.asyncio
async def test_telemetry_resync_successful():
    """Test /api/telemetry/resync when all upstream sources are reachable."""
    with respx.mock(assert_all_called=False) as respx_mock:
        # Mock CISA KEV feed
        respx_mock.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").respond(
            200,
            json={"title": "CISA KEV", "catalogVersion": "2026.10.22", "count": 2, "vulnerabilities": []},
        )
        # Mock NVD probe
        respx_mock.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228").respond(
            200, json={"vulnerabilities": []}
        )
        # Mock EPSS probe
        respx_mock.get("https://api.first.org/data/v1/epss?cve=CVE-2021-44228").respond(
            200, json={"status": "OK", "data": []}
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/telemetry/resync")
            assert resp.status_code == 200
            data = resp.json()

            assert data["status"] in ("success", "partial")
            assert "sources" in data
            assert "cisa_kev" in data["sources"]
            assert "nvd" in data["sources"]
            assert "epss" in data["sources"]


@pytest.mark.asyncio
async def test_telemetry_resync_cisa_403_fallback_preserves_catalog():
    """Test /api/telemetry/resync when CISA returns HTTP 403 Forbidden (cloud host condition).

    Verifies it reports partial status, documents HTTP 403 error, and does NOT wipe local catalog.
    """
    from app.services.cisa_client import cisa_client
    cisa_client.load_seed_catalog()

    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").respond(
            403, text="Forbidden by Cloudflare"
        )
        respx_mock.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228").respond(
            200, json={"vulnerabilities": []}
        )
        respx_mock.get("https://api.first.org/data/v1/epss?cve=CVE-2021-44228").respond(
            200, json={"status": "OK", "data": []}
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/telemetry/resync")
            assert resp.status_code == 200
            data = resp.json()

            assert data["status"] == "partial"
            cisa_res = data["sources"]["cisa_kev"]
            assert cisa_res["status"] == "cached_fallback"
            assert "403" in cisa_res["error"]
            assert cisa_res["count"] > 0  # Preserved local cached catalog!
