"""API tests (FastAPI TestClient, temp DB, API key set before import)."""
import os
import tempfile

_TMP = tempfile.mkdtemp()
os.environ["PHISH_API_KEY"] = "test-key-123"
os.environ["PHISH_DB_PATH"] = os.path.join(_TMP, "test.db")

from fastapi.testclient import TestClient  # noqa: E402

from server.main import app  # noqa: E402

HEADERS = {"X-API-Key": "test-key-123"}


def test_health_is_open():
    with TestClient(app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_missing_api_key_is_rejected():
    with TestClient(app) as client:
        resp = client.post("/analyze", json={"url": "https://www.github.com"})
    assert resp.status_code == 401


def test_wrong_api_key_is_rejected():
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            json={"url": "https://www.github.com"},
            headers={"X-API-Key": "wrong-key"},
        )
    assert resp.status_code == 401


def test_analyze_legit_and_phishing_and_history():
    with TestClient(app) as client:
        legit = client.post(
            "/analyze", json={"url": "https://www.github.com"}, headers=HEADERS
        )
        assert legit.status_code == 200
        assert legit.json()["label"] == "LEGIT"

        # example.invalid never resolves, so the fetch fails and the
        # analysis falls back to URL features alone.
        phish = client.post(
            "/analyze",
            json={"url": "https://paypal.com.secure-login.tk/verify"},
            headers=HEADERS,
        )
        assert phish.status_code == 200
        assert phish.json()["label"] == "PHISHING"

        by_id = client.get(f"/analyze/{legit.json()['id']}", headers=HEADERS)
        assert by_id.status_code == 200
        assert by_id.json()["url"] == "https://www.github.com"

        history = client.get("/history", headers=HEADERS)
        assert history.status_code == 200
        urls = [row["url"] for row in history.json()]
        assert "https://www.github.com" in urls
        assert "https://paypal.com.secure-login.tk/verify" in urls

        stats = client.get("/stats", headers=HEADERS)
        assert stats.status_code == 200
        assert stats.json()["total"] >= 2
        assert stats.json()["phishing"] >= 1
        assert stats.json()["legit"] >= 1


def test_unknown_analysis_id_is_404():
    with TestClient(app) as client:
        resp = client.get("/analyze/999999", headers=HEADERS)
    assert resp.status_code == 404
