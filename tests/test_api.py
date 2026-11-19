import json

import pytest

import app as application
import checker


@pytest.fixture
def client(monkeypatch):
    application.app.config["TESTING"] = True
    monkeypatch.setattr(checker, "analyze", lambda u: {"input": u, "url": u, "signals": [], "chain": [], "final_url": u})
    monkeypatch.setattr(checker, "verdict", lambda r: {"level": "clear", "counts": {}, "signals": []})
    application._HITS.clear()
    return application.app.test_client()


def test_check_returns_json(client):
    r = client.post("/api/check", json={"url": "example.com"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["url"] == "example.com" and body["verdict"]["level"] == "clear"


def test_empty_url_rejected(client):
    r = client.post("/api/check", json={"url": ""})
    assert r.status_code == 400 and r.get_json()["error"] == "empty"


def test_cors_allows_trusted_origin(client):
    r = client.post("/api/check", json={"url": "example.com"}, headers={"Origin": "https://lab.vulpfest.com"})
    assert r.headers.get("Access-Control-Allow-Origin") == "https://lab.vulpfest.com"


def test_cors_blocks_unknown_origin(client):
    r = client.post("/api/check", json={"url": "example.com"}, headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_preflight_options(client):
    r = client.open("/api/check", method="OPTIONS", headers={"Origin": "https://lab.vulpfest.com"})
    assert r.status_code == 204
    assert r.headers.get("Access-Control-Allow-Origin") == "https://lab.vulpfest.com"


def test_rate_limit(client):
    application.RATE_MAX = 3
    application._HITS.clear()
    codes = [client.post("/api/check", json={"url": "example.com"},
                         environ_overrides={"REMOTE_ADDR": "9.9.9.9"}).status_code for _ in range(5)]
    assert 429 in codes