import pytest
import httpx
from pathlib import Path
from unittest.mock import patch
from app.main import app, get_dist_dir


@pytest.mark.asyncio
async def test_spa_root_serves_html():
    """Verify that GET / returns the production index.html when dist exists."""
    dist_dir = get_dist_dir()
    if not (dist_dir.exists() and (dist_dir / "index.html").exists()):
        pytest.skip("dist/index.html does not exist in current environment")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "ThreatPrior" in response.text or "<!doctype html>" in response.text.lower()


@pytest.mark.asyncio
async def test_spa_client_routes_serve_index_html():
    """Verify that frontend client-side routes (e.g. /history) fallback to index.html."""
    dist_dir = get_dist_dir()
    if not (dist_dir.exists() and (dist_dir / "index.html").exists()):
        pytest.skip("dist/index.html does not exist in current environment")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/history")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")

        # Also test nested client-side route
        nested_resp = await client.get("/vulnerabilities/CVE-2021-44228")
        assert nested_resp.status_code == 200
        assert "text/html" in nested_resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_api_routes_return_json():
    """Verify that API endpoints still return application/json and are not shadowed by the SPA fallback."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        data = response.json()
        assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_unknown_api_routes_do_not_return_html():
    """Verify that unknown /api/* requests return 404 JSON, never falling through to index.html."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Check /api/unknown
        response = await client.get("/api/unknown")
        assert response.status_code == 404
        assert "text/html" not in response.headers.get("content-type", "")
        data = response.json()
        assert "detail" in data
        assert "API endpoint '/api/unknown' not found" in data["detail"]

        # Check /api directly
        api_root_resp = await client.get("/api")
        assert api_root_resp.status_code == 404
        assert "text/html" not in api_root_resp.headers.get("content-type", "")


def test_get_dist_dir_resolution():
    """Verify get_dist_dir resolves a valid Path without raising exceptions."""
    resolved = get_dist_dir()
    assert isinstance(resolved, Path)


@pytest.mark.asyncio
async def test_backend_operates_when_dist_absent(tmp_path):
    """Verify backend API still works if dist does not exist (backend-only environments)."""
    from fastapi import FastAPI
    from app.routers import health

    # Construct test app mimicking main.py when dist/ does not exist
    test_app = FastAPI()
    test_app.include_router(health.router)

    # dist_dir is non-existent
    non_existent = tmp_path / "non_existent_dist"
    assert not non_existent.exists()
    # No static mount or catch-all added when dist is absent

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=test_app), base_url="http://test") as client:
        res = await client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "traversal_path",
    [
        "/..%2fbackend/.env.example",
        "/..%2fbackend/requirements.txt",
        "/..%5cbackend/requirements.txt",
        "/%2e%2e%2fbackend/.env.example",
        "/..%2f..%2fpackage.json",
        "/%2e%2e%2f%2e%2e%2fREADME.md",
        "/..%2f..%2f..%2fbackend%2fapp%2fmain.py",
        "/..%5c..%5cbackend%5capp%5cmain.py",
        "/%2e%2e%5cbackend%2fapp%2fmain.py",
        "/..%2f.env",
        "/..%2fbackend%2f.env",
        "/etc/passwd",
        "/C:/Windows/win.ini",
        "/dist/../../backend/.env.example",
    ],
)
async def test_spa_path_traversal_attempts_rejected(traversal_path: str):
    """Verify that path traversal attempts are strictly rejected and never return backend or system files."""
    dist_dir = get_dist_dir()
    if not (dist_dir.exists() and (dist_dir / "index.html").exists()):
        pytest.skip("dist/index.html does not exist in current environment")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(traversal_path)
        # Should be 404, never 200 containing file contents
        assert response.status_code == 404
        # Assert file contents are never leaked
        assert "AWS_SECRET_ACCESS_KEY" not in response.text
        assert "fastapi" not in response.text.lower() or "<!doctype html>" in response.text.lower()
        assert "uvicorn" not in response.text.lower()
        assert "ThreatPrior AI" not in response.text or "<!doctype html>" in response.text.lower()


@pytest.mark.asyncio
async def test_spa_null_byte_injection_rejected():
    """Verify that null-byte path injections are rejected with 404."""
    dist_dir = get_dist_dir()
    if not (dist_dir.exists() and (dist_dir / "index.html").exists()):
        pytest.skip("dist/index.html does not exist in current environment")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/index.html%00.txt")
        assert response.status_code == 404

