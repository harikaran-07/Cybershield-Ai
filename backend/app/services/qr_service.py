"""QR analysis service — decode-safe content triage.

The Android client decodes QR codes locally with ML Kit and sends the decoded
string here. We classify the payload type and route URLs into URL analysis.
Payment payloads (EMVCo) are parsed read-only — payments are never initiated.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from app.services.url_service import analyze_url

URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
WIFI_RE = re.compile(r"^WIFI:S:(.*?);(?:T:(.*?);)?P:(.*?);;", re.IGNORECASE)
# EMVCo payment QR (EMV QR Code payload starts with payload format indicator "00")
EMV_TAGS = {"00": "Payload Format Indicator", "01": "Point of Initiation Method",
            "26": "Merchant Account Info", "52": "MCC", "53": "Currency", "54": "Amount",
            "58": "Country", "59": "Merchant Name", "60": "Merchant City"}


def _parse_emv(payload: str) -> dict:
    """Read-only parse of top-level EMVCo TLV fields. Never initiates payments."""
    out: dict[str, str] = {}
    i = 0
    try:
        while i + 4 <= len(payload):
            tag = payload[i:i + 2]
            length = int(payload[i + 2:i + 4])
            value = payload[i + 4:i + 4 + length]
            if tag in EMV_TAGS:
                out[tag] = f"{EMV_TAGS[tag]}: {value[:80]}"
            i += 4 + length
    except Exception:
        pass
    return out


def _classify_payload(content: str) -> tuple[str, str]:
    """Return (payload_type, note)."""
    c = content.strip()
    if WIFI_RE.match(c):
        return "WIFI_CREDENTIALS", "QR joins a Wi-Fi network — verify the network name before connecting."
    if c.upper().startswith("BEGIN:VCARD") or c.upper().startswith("VCARD"):
        return "CONTACT_CARD", "QR contains contact details."
    if c.upper().startswith(("TEL:", "SMSTO:", "mailto:", "MATMSG:")):
        return "COMMUNICATION", "QR triggers a call/SMS/email action."
    if c.upper().startswith("OTPAUTH:"):
        return "OTP_SECRET", "QR contains a 2FA secret — do not share it."
    if re.match(r"^\d{20,}", c) and c.isdigit():
        return "POSSIBLE_PAYMENT", "Numeric payload consistent with a payment QR code."
    if c.startswith("0002") or (c[:2].isdigit() and len(c) > 20 and "5802" in c[:60]):
        return "EMV_PAYMENT", "QR matches EMVCo payment format."
    return "TEXT", "Plain text QR content."


def analyze_qr(content: str, qr_format: str = "QR_CODE", device_id: str | None = None) -> dict:
    """Triage decoded QR content. URLs are analyzed via URL service."""
    content = (content or "").strip()
    if not content:
        return {"payload_type": "EMPTY", "notes": ["QR content is empty"],
                "indicators": [], "risk_score": 0, "severity": "SAFE",
                "classification": "SAFE", "recommendation": ""}

    payload_type, note = _classify_payload(content)
    indicators = [note] if note else []
    notes: list[str] = []
    url_result: dict | None = None
    payment_fields: dict | None = None

    if payload_type in ("EMV_PAYMENT", "POSSIBLE_PAYMENT"):
        payment_fields = _parse_emv(content)
        indicators.append("Payment QR code — confirm the merchant and amount in your banking app before paying")
        if payment_fields.get("01", "").endswith("12"):
            indicators.append("Dynamic payment QR (single-use) — extra caution with sources you don't know")
        notes.append("Payment details are read-only; CyberShield never initiates payments.")
    elif payload_type == "WIFI_CREDENTIALS":
        indicators.append("Check the network name — attackers use lookalike hotspots")

    url_match = URL_RE.search(content)
    if url_match:
        url = url_match.group(0).rstrip(".,;:!?)\"'")
        url_result = analyze_url(url, device_id)
        indicators.extend(url_result["indicators"])
        if url_result["label"] == "PHISHING":
            indicators.insert(0, "QR contains an external URL with phishing characteristics")
        else:
            indicators.insert(0, "QR contains an external URL")

    # Risk aggregation
    base = 0
    if payload_type in ("EMV_PAYMENT", "POSSIBLE_PAYMENT"):
        base = 45
    elif payload_type == "WIFI_CREDENTIALS":
        base = 35
    elif payload_type == "OTP_SECRET":
        base = 25
    elif payload_type == "COMMUNICATION":
        base = 20
    if url_result:
        url_risk = url_result["risk_score"]
        risk_score = min(100, max(base, int(0.6 * url_risk + 0.4 * base + 15)))
    else:
        risk_score = min(100, base)

    from app.models.schemas import severity_for_score
    severity = severity_for_score(risk_score)
    classification = ("PHISHING" if (url_result and url_result["label"] == "PHISHING")
                      else "SUSPICIOUS" if risk_score >= 40 else "SAFE")
    recommendation = ("Do not scan QR codes from unknown posters, emails, or messages. "
                      "Verify payment QRs with the payee through another channel."
                      if risk_score >= 40 else
                      "QR content looks low-risk. Stay cautious with payment and login QRs.")

    return {
        "payload_type": payload_type,
        "qr_format": qr_format,
        "notes": notes,
        "payment_fields": payment_fields,
        "url_analysis": url_result,
        "indicators": indicators or ["No notable QR indicators"],
        "risk_score": risk_score,
        "severity": severity,
        "classification": classification,
        "recommendation": recommendation,
        "content_length": len(content),
        "content_preview": content[:80],
    }
