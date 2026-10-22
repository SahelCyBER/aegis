"""The Ask-AI router (and the RAG routes riding on it) live under /api/v1."""
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

MAIN_PY = Path(__file__).resolve().parents[2] / "app" / "main.py"


def test_main_mounts_ask_router_under_api_v1():
    src = MAIN_PY.read_text()
    assert re.search(r'include_router\(ask_ai_router\.router,\s*prefix="/api/v1"\)', src)


@pytest.fixture
def client():
    try:
        from app.api import ask_ai
    except Exception as e:  # pragma: no cover - env without full deps
        pytest.skip(f"ask_ai not importable here: {e}")
    app = FastAPI()
    app.include_router(ask_ai.router, prefix="/api/v1")
    return TestClient(app)


def test_ask_resolves_under_api_v1(client):
    # Auth/validation may reject the empty call, but it must not be a 404.
    assert client.post("/api/v1/ask", json={}).status_code != 404


def test_ask_rag_status_resolves_under_api_v1(client):
    assert client.get("/api/v1/ask/rag/status").status_code != 404


def test_bare_ask_is_gone(client):
    assert client.post("/ask", json={}).status_code == 404
