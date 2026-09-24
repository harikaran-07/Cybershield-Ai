"""Tests for v2 endpoints: text/url/apk/correlate/events/summary."""
import io
import zipfile

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _make_apk(perms: list[str]) -> bytes:
    """Build a minimal fake APK (ZIP with manifest-like string pool)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Binary manifest: permissions appear as UTF-16LE strings
        manifest = "".join(p for p in perms).encode("utf-16-le")
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n" + bytes(100))
    return buf.getvalue()


def test_v2_text_safe():
    r = client.post("/api/text/analyze", json={"text": "Hey, lunch at noon?"})
    assert r.status_code == 200
    assert r.json()["risk_score"] <= 30


def test_v2_text_scam():
    r = client.post("/api/text/analyze", json={
        "text": "URGENT your account will be suspended verify immediately http://paypa1-verify.tk/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] >= 50
    assert body["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_v2_text_empty_rejected():
    r = client.post("/api/text/analyze", json={"text": "   "})
    assert r.status_code == 422


def test_v2_url_ok():
    r = client.post("/api/url/analyze?url=https://www.wikipedia.org")
    assert r.status_code == 200
    assert r.json()["risk_score"] <= 35


def test_v2_url_invalid():
    r = client.post("/api/url/analyze?url=not a url")
    assert r.status_code == 422


def test_v2_apk_safe():
    apk = _make_apk(["android.permission.INTERNET"])
    r = client.post("/api/apk/analyze",
                    files={"file": ("clean.apk", apk, "application/vnd.android.package-archive")})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "SAFE"
    assert body["entry_count"] >= 2
    assert len(body["sha256"]) == 64


def test_v2_apk_risky():
    apk = _make_apk([
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.CAMERA",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    ])
    r = client.post("/api/apk/analyze",
                    files={"file": ("suspicious.apk", apk, "application/vnd.android.package-archive")})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] >= 50
    assert body["classification"] in ("SUSPICIOUS", "RISKY")
    assert any("SMS" in i or "high-risk" in i for i in body["indicators"])


def test_v2_apk_not_apk_rejected():
    r = client.post("/api/apk/analyze",
                    files={"file": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 422


def test_v2_correlate():
    r = client.post("/api/threat/correlate", json={"events": [
        {"event_type": "SMS_SCAM", "risk_score": 85},
        {"event_type": "URL_PHISHING", "risk_score": 90},
        {"event_type": "NETWORK_ANOMALY", "risk_score": 70},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["combined_risk"] >= 80
    assert body["severity"] in ("HIGH", "CRITICAL")


def test_v2_correlate_empty():
    r = client.post("/api/threat/correlate", json={"events": []})
    assert r.status_code == 422


def test_v2_events():
    r = client.get("/api/security/events")
    assert r.status_code == 200
    assert "events" in r.json()


def test_v2_summary():
    r = client.get("/api/security/summary")
    assert r.status_code == 200
    body = r.json()
    for key in ("security_score", "status", "total_scans", "by_type", "by_severity"):
        assert key in body


def test_v2_file_analyze():
    r = client.post("/api/file/analyze",
                    files={"file": ("invoice.pdf.exe", b"MZ\x90" + b"A" * 300,
                                    "application/octet-stream")})
    assert r.status_code == 200
    assert r.json()["risk_score"] >= 30
