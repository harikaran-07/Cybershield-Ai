"""Scan orchestration — pipelines each scan type through detection layers.

Flow per scan: Detection (rules/ML/NLP) → Risk Engine → persist → Threat
Correlation → LLM explanation (never affecting the score).
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.database_models import FileRecord, MessageRecord, ScanResult, UrlRecord
from app.models.schemas import severity_for_score
from app.services import (app_security_service, file_service, llm_service,
                          network_service, nlp_service, qr_service, url_service)
from app.services.risk_engine import RiskInputs, compute_risk, explain_risk
from app.services.threat_correlation import maybe_build_chain, record_event


def _new_scan_id() -> str:
    return uuid.uuid4().hex[:16]


def _finalize(db: Session, scan_id: str, scan_type: str, device_id: str | None,
              classification: str, risk: int, confidence: float,
              indicators: list[str], methods: list[str], recommendation: str,
              event_type: str, evidence: dict, raw_content: str | None,
              risk_detail: dict) -> dict:
    """Persist scan + event, run correlation, attach explanation, build response."""
    sev = severity_for_score(risk)

    # Privacy: raw content persisted only when explicitly enabled
    stored_raw = raw_content if settings.STORE_RAW_CONTENT else None

    scan = ScanResult(scan_id=scan_id, device_id=device_id, type=scan_type,
                      classification=classification, risk_score=risk, severity=sev,
                      confidence=confidence, indicators=indicators,
                      detection_methods=methods, recommendation=recommendation,
                      raw_content=stored_raw)
    db.add(scan)
    db.flush()

    # Record structured event (minimal evidence) and attempt chain correlation
    event = record_event(db, device_id, scan_id, event_type, sev, risk, evidence)
    chain_info = maybe_build_chain(db, device_id, event)

    # LLM explanation — strictly AFTER detection; result unaffected by it
    explanation, llm_used = None, False
    if settings.LLM_EXPLANATIONS_ENABLED:
        out = llm_service.explain_threat(
            threat_type=event_type.replace("_", " ").title(),
            risk_score=risk, severity=sev, indicators=indicators)
        explanation, llm_used = out["explanation"], out["llm_used"]

    return {
        "scan_id": scan_id,
        "type": scan_type,
        "risk_score": risk,
        "severity": sev,
        "classification": classification,
        "confidence": round(confidence, 3),
        "indicators": indicators,
        "detection_methods": methods,
        "recommendation": recommendation,
        "ai_explanation": explanation,
        "ai_llm_used": llm_used,
        "risk_breakdown": risk_detail,
        "correlated_chain": chain_info,
    }


# ---------------------------------------------------------------------------
# Message (SMS/chat/email text) scanning
# ---------------------------------------------------------------------------
def analyze_message(db: Session, text: str, device_id: str | None) -> dict:
    scan_id = _new_scan_id()
    nlp_out = nlp_service.analyze_message_nlp(text)
    nlp = nlp_out["nlp"]
    rules = nlp_out["rules"]

    # Extracted URLs get their own URL analysis
    url_results = []
    max_url_prob = None
    url_indicators = []
    for u in rules["urls"][:5]:
        ur = url_service.analyze_url(u)
        ur["url"] = u
        url_results.append(ur)
        max_url_prob = max(max_url_prob or 0, ur["probability"])
        if ur["label"] in ("PHISHING", "SUSPICIOUS"):
            url_indicators.append(f"Suspicious URL: {u[:80]}")

    rule_score = rules["rule_score"]
    # Blend rule score with URL rule evidence when URLs exist
    if url_results:
        url_rule = max(min(100, 0), 0)
        rule_score = max(rule_score, max((r["risk_score"] for r in url_results), default=0))

    risk = compute_risk(RiskInputs(
        # NLP contributes THREAT evidence only when the model predicts a threat
        # class. A confident SAFE prediction must not raise risk even when the
        # multi-class confidence is high (multi-class ≠ binary- threat semantics).
        nlp_probability=nlp["probability"] if nlp["method"] != "none" and nlp["label"] != "SAFE" else None,
        url_probability=max_url_prob,
        rule_score=rule_score if rule_score > 0 else None,
        indicator_count=len(nlp["indicators"]) + len(url_indicators),
    ))

    # Classification: worst of NLP label and URL verdict
    label = nlp["label"]
    if url_results and any(r["label"] == "PHISHING" for r in url_results) and label == "SAFE":
        label = "PHISHING"
    elif label == "SAFE" and risk.risk_score >= 40:
        label = "SUSPICIOUS"

    indicators = list(dict.fromkeys(nlp["indicators"] + url_indicators))
    methods = ["Rule Engine"]
    methods.append({
        "roberta": "RoBERTa NLP",
        "trained_sklearn": "Trained NLP (TF-IDF)",
        "fallback_heuristic": "NLP (fallback)",
    }.get(nlp["method"], nlp["method"]))
    if url_results:
        methods.append("URL Analysis")

    recommendation = ("Do not open the link. Verify through the organization's official "
                      "application or website." if label in ("SCAM", "PHISHING") else
                      "Message shows suspicious traits. Avoid sharing personal information."
                      if label == "SUSPICIOUS" else
                      "No strong scam indicators. Continue to stay cautious with links.")

    # Persist message summary (never raw text by default)
    db.add(MessageRecord(scan_id=scan_id, length=len(text), url_count=len(rules["urls"]),
                         urgency_score=rules["urgency_score"], label=label))

    risk_detail = risk.as_dict()
    risk_detail["risk_explanation"] = explain_risk(risk)
    return _finalize(db, scan_id, "SMS", device_id, label, risk.risk_score,
                     nlp["probability"], indicators, methods, recommendation,
                     event_type="MESSAGE_SCAM" if label in ("SCAM", "SPAM") else "MESSAGE_SCANNED",
                     evidence={"detail": f"label={label}", "label": label},
                     raw_content=text, risk_detail=risk_detail) | {"url_results": url_results}


# ---------------------------------------------------------------------------
# URL scanning
# ---------------------------------------------------------------------------
def analyze_url_scan(db: Session, url: str, device_id: str | None) -> dict:
    scan_id = _new_scan_id()
    ur = url_service.analyze_url(url)
    risk = compute_risk(RiskInputs(
        url_probability=ur["probability"],
        rule_score=max(ur["risk_score"], 0),
        indicator_count=len(ur["indicators"]),
    ))
    label = ur["label"]
    detail = risk.as_dict()
    detail["risk_explanation"] = explain_risk(risk)
    db.add(UrlRecord(scan_id=scan_id, url_hash=ur["url_hash"], host=ur["host"],
                     label=label, probability=ur["probability"]))
    resp = _finalize(db, scan_id, "URL", device_id, label, risk.risk_score,
                     ur["probability"], ur["indicators"],
                     [ur["method"], "Rule Engine"], ur["recommendation"],
                     event_type="URL_PHISHING" if label == "PHISHING" else
                                "URL_SUSPICIOUS" if label == "SUSPICIOUS" else "URL_SCANNED",
                     evidence={"host": ur["host"], "label": label},
                     raw_content=url, risk_detail=detail)
    resp["features"] = ur["features"]
    resp["note"] = ur["note"]
    return resp


# ---------------------------------------------------------------------------
# QR scanning (content already decoded client-side by ML Kit)
# ---------------------------------------------------------------------------
def analyze_qr_scan(db: Session, content: str, qr_format: str,
                    device_id: str | None) -> dict:
    scan_id = _new_scan_id()
    qr = qr_service.analyze_qr(content, qr_format, device_id)

    url_prob = None
    if qr.get("url_analysis"):
        url_prob = qr["url_analysis"]["probability"]
    risk = compute_risk(RiskInputs(
        url_probability=url_prob,
        rule_score=qr["risk_score"],
        indicator_count=len(qr["indicators"]),
    ))
    combined = max(qr["risk_score"], risk.risk_score) if risk.risk_score else qr["risk_score"]
    sev = severity_for_score(combined)
    label = qr["classification"]
    detail = risk.as_dict()
    detail["risk_explanation"] = explain_risk(risk)

    event_type = "QR_PHISHING" if label == "PHISHING" else "QR_SCANNED"
    resp = _finalize(db, scan_id, "QR", device_id, label, combined,
                     url_prob or 0.5, qr["indicators"],
                     ["QR Triage", "URL Analysis"] if qr.get("url_analysis") else ["QR Triage"],
                     qr["recommendation"], event_type=event_type,
                     evidence={"payload_type": qr["payload_type"], "detail": qr["payload_type"]},
                     raw_content=content if settings.STORE_RAW_CONTENT else None,
                     risk_detail=detail)
    resp["payload_type"] = qr["payload_type"]
    resp["payment_fields"] = qr.get("payment_fields")
    resp["url_analysis"] = qr.get("url_analysis")
    return resp


# ---------------------------------------------------------------------------
# File scanning (bytes uploaded via multipart)
# ---------------------------------------------------------------------------
def analyze_file_scan(db: Session, filename: str, data: bytes,
                      mime: str | None, device_id: str | None) -> dict:
    scan_id = _new_scan_id()
    fr = file_service.analyze_file(filename, data, mime)
    risk = compute_risk(RiskInputs(file_risk=fr["risk_score"],
                                   indicator_count=len(fr["indicators"])))
    score = max(fr["risk_score"], risk.risk_score)
    detail = risk.as_dict()
    detail["risk_explanation"] = explain_risk(risk)

    db.add(FileRecord(scan_id=scan_id, sha256=fr["sha256"], filename=fr["filename"],
                      mime_type=fr.get("mime_type"), size_bytes=fr["size_bytes"],
                      label=fr["label"]))
    resp = _finalize(db, scan_id, "FILE", device_id, fr["label"], score,
                     min(1.0, 0.4 + len(fr["indicators"]) * 0.1), fr["indicators"],
                     fr["detection_methods"], fr["recommendation"],
                     event_type="FILE_RISKY" if fr["label"] != "SAFE" else "FILE_SCANNED",
                     evidence={"detail": fr["filename"], "label": fr["label"]},
                     raw_content=None, risk_detail=detail)
    resp.setdefault("details", {})["file"] = {
        k: fr[k] for k in ("filename", "mime_type", "size_bytes",
                           "sha256", "extension_mismatch", "double_extension")}
    resp["metadata_notes"] = fr["metadata_notes"]
    resp["note"] = fr["note"]
    return resp


# ---------------------------------------------------------------------------
# App security
# ---------------------------------------------------------------------------
def analyze_app_security(db: Session, device_id: str | None, apps: list[dict]) -> dict:
    result = app_security_service.analyze_apps(apps)
    worst = max((a["risk_score"] for a in result["apps"]), default=0)
    risk = compute_risk(RiskInputs(app_risk=worst))
    # Persist top risky apps
    from app.models.database_models import AppSecurityResult
    for a in result["apps"][:20]:
        if a["label"] != "SAFE":
            db.add(AppSecurityResult(device_id=device_id, package_name=a["package_name"],
                                     app_label=a["label"], risk_score=a["risk_score"],
                                     sensitive_permissions=[p["permission"] for p in
                                                            a["permissions"] if p["category"] == "HIGH"]))
    return {"risk_score": risk.risk_score, "severity": severity_for_score(worst),
            **result, "risk_breakdown": risk.as_dict()}


# ---------------------------------------------------------------------------
# Network anomaly
# ---------------------------------------------------------------------------
def analyze_network_scan(db: Session, device_id: str | None,
                         stats: list[dict], window_minutes: int) -> dict:
    from app.models.database_models import NetworkAnomaly
    na = network_service.analyze_network(stats, window_minutes)
    risk = compute_risk(RiskInputs(
        network_anomaly=na["anomaly_score"] if na["verdict"] != "NORMAL" else 0.0))
    db.add(NetworkAnomaly(device_id=device_id, verdict=na["verdict"],
                          anomaly_score=na["anomaly_score"],
                          destinations=na["flagged_destinations"]))
    event_type = {"ANOMALOUS": "NETWORK_ANOMALY", "SUSPICIOUS": "NETWORK_SUSPICIOUS"}.get(
        na["verdict"], "NETWORK_NORMAL")
    if na["verdict"] != "NORMAL":
        record_event(db, device_id, None, event_type, na["verdict"],
                     int(na["anomaly_score"] * 100),
                     {"detail": ", ".join(na["flagged_destinations"][:3])})
    return {"scan_id": _new_scan_id(), "type": "NETWORK", **na,
            "risk_score": risk.risk_score,
            "severity": severity_for_score(int(na["anomaly_score"] * 100)) if na["verdict"] != "NORMAL" else "SAFE",
            "risk_breakdown": risk.as_dict()}
