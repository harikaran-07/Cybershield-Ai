"""Smoke test: app imports, endpoints respond, detection works."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert "nlp_model" in body


def test_message_scan_scam():
    r = client.post("/api/v1/analyze/message", json={
        "text": "URGENT: Your account will be suspended. Verify immediately: http://paypa1-verify.xyz/login",
        "device_id": "test-device"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["classification"] in ("SCAM", "PHISHING", "SUSPICIOUS")
    assert body["risk_score"] >= 40
    assert body["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert body["scan_id"]
    assert any("URL" in m or "Rule" in m for m in body["detection_methods"])


def test_message_scan_safe():
    r = client.post("/api/v1/analyze/message", json={
        "text": "Hey, lunch tomorrow at noon? See you at the usual place!"})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] <= 30
    assert body["classification"] == "SAFE"


def test_url_scan_phishing():
    r = client.post("/api/v1/analyze/url", json={
        "url": "http://paypal-secure-login.verify-account.tk/webscr?cmd=login&email=user@test.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] >= 50
    assert body["indicators"]


def test_url_scan_normal():
    r = client.post("/api/v1/analyze/url", json={"url": "https://www.wikipedia.org"})
    assert r.status_code == 200
    assert r.json()["risk_score"] <= 35


def test_url_scan_invalid():
    r = client.post("/api/v1/analyze/url", json={"url": "   "})
    assert r.status_code == 422


def test_qr_scan_url():
    r = client.post("/api/v1/analyze/qr", json={
        "content": "http://secure-verify-account.xyz/login?id=12345"})
    assert r.status_code == 200
    assert r.json()["risk_score"] >= 40


def test_file_scan(tmp_path):
    # Fake 'PDF' that's actually an EXE header — mismatch should be flagged
    r = client.post("/api/v1/analyze/file",
                    files={"file": ("invoice.pdf.exe", b"MZ\x90\x00" + b"A" * 500,
                                    "application/octet-stream")})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] >= 30
    assert body["classification"] in ("SUSPICIOUS", "RISKY")
    assert body["details"]["file"]["sha256"]
    assert body["details"]["file"]["double_extension"] is True


def test_file_scan_safe_png():
    r = client.post("/api/v1/analyze/file",
                    files={"file": ("photo.png",
                                    b"\x89PNG\r\n\x1a\n" + b"\x00" * 200,
                                    "image/png")})
    assert r.status_code == 200
    assert r.json()["risk_score"] <= 30


def test_empty_message_rejected():
    r = client.post("/api/v1/analyze/message", json={"text": "   "})
    assert r.status_code == 422


def test_chain_correlation():
    r = client.post("/api/v1/threats/chain", json={
        "events": [
            {"event_type": "SMS_SCAM", "risk_score": 85, "detail": "Scam SMS detected"},
            {"event_type": "URL_PHISHING", "risk_score": 88, "detail": "Phishing URL"},
            {"event_type": "NETWORK_ANOMALY", "risk_score": 70, "detail": "Anomalous traffic"},
        ]})
    assert r.status_code == 200
    body = r.json()
    assert body["combined_risk"] >= 75
    assert body["severity"] in ("HIGH", "CRITICAL")
    assert body["contributing_signals"]


def test_dashboard():
    r = client.get("/api/v1/dashboard")
    assert r.status_code == 200
    body = r.json()
    for key in ("total_scans", "safe_count", "threats_detected", "threats_by_type"):
        assert key in body


def test_threat_history():
    r = client.get("/api/v1/threats")
    assert r.status_code == 200
    assert "total" in r.json()
    assert "threats" in r.json()


def test_delete_history():
    r = client.delete("/api/v1/threats/history")
    assert r.status_code == 200
    assert r.json()["status"] == "history cleared"


def test_ai_explain_graceful_without_ollama():
    r = client.post("/api/v1/ai/explain", json={
        "threat_type": "Phishing URL", "risk_score": 88, "severity": "HIGH",
        "indicators": ["Suspicious URL", "Urgent language"]})
    assert r.status_code == 200
    body = r.json()
    assert body["explanation"]
    # llm_used may be True or False depending on environment; both valid
    assert isinstance(body["llm_used"], bool)
