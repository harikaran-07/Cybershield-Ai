"""Threat Correlation Engine — links related events into attack chains.

A chain emerges when multiple independent signals (SMS scam, phishing URL,
suspicious domain, network anomaly) occur in a short time window, optionally
sharing a host. The engine explains which signals contributed and raises the
combined risk accordingly.
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.database_models import ThreatChain, ThreatEvent
from app.models.schemas import ChainLink, severity_for_score

logger = logging.getLogger(__name__)

# How far apart events may be and still be considered one chain
WINDOW_MINUTES = 30
# Event types ordered by typical attack-chain position (earlier → later)
CHAIN_ORDER = {
    "SMS_SCAM": 1, "MESSAGE_SCAM": 1, "QR_PHISHING": 2, "URL_PHISHING": 2,
    "URL_SUSPICIOUS": 2, "SUSPICIOUS_DOMAIN": 3, "REDIRECT_ANOMALY": 3,
    "LOGIN_PAGE_RISK": 4, "FILE_RISKY": 3, "APP_RISKY": 3,
    "NETWORK_ANOMALY": 5, "FILE_SCANNED": 0, "MESSAGE_SCANNED": 0,
}
# Pairs that strongly indicate a chain when they co-occur
STRONG_PAIRS = {
    ("SMS_SCAM", "URL_PHISHING"), ("MESSAGE_SCAM", "URL_PHISHING"),
    ("URL_PHISHING", "NETWORK_ANOMALY"), ("QR_PHISHING", "URL_PHISHING"),
    ("SMS_SCAM", "NETWORK_ANOMALY"), ("SUSPICIOUS_DOMAIN", "NETWORK_ANOMALY"),
}
ESCALATION_BONUS = {"PAIR": 10, "TRIPLE": 18, "HOST_LINK": 8}


def _as_aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; always compare in aware UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _event_sort_key(e: Any) -> tuple:
    order = CHAIN_ORDER.get(e.event_type, 99)
    ts = e.detected_at or datetime.now(UTC)
    return (order, ts)


def correlate_events(events: list[ThreatEvent | ChainLink]) -> dict:
    """Correlate a list of events into an attack-chain assessment.

    Accepts either DB ThreatEvent rows or API ChainLink items. Returns a dict
    with chain_types, combined_risk, severity, explanation, contributing_signals.
    """
    if not events:
        return {"chain_types": [], "combined_risk": 0, "severity": "SAFE",
                "explanation": "No events to correlate", "contributing_signals": []}

    # Normalize to a common shape
    norm: list[dict] = []
    for e in events:
        if isinstance(e, ChainLink):
            norm.append({"event_type": e.event_type, "risk_score": e.risk_score,
                         "scan_id": e.scan_id, "detail": e.detail, "host": None,
                         "detected_at": datetime.now(UTC)})
            continue
        norm.append({"event_type": e.event_type, "risk_score": e.risk_score or 0,
                     "scan_id": e.scan_id, "detail": (e.evidence or {}).get("detail", ""),
                     "host": (e.evidence or {}).get("host"),
                     "detected_at": _as_aware(e.detected_at or datetime.now(UTC))})


    # Filter to risky events and sort into chain order
    risky = [n for n in norm if n["risk_score"] >= 40 or n["event_type"] in CHAIN_ORDER]
    risky.sort(key=lambda n: (CHAIN_ORDER.get(n["event_type"], 99), n["detected_at"]))
    types = [n["event_type"] for n in risky]
    unique_types = list(dict.fromkeys(types))

    # Base combined risk: max of the individual scores, escalated by correlation
    max_risk = max((n["risk_score"] for n in risky), default=0)
    avg_risk = (sum(n["risk_score"] for n in risky) / len(risky)) if risky else 0
    combined = int(max(max_risk, avg_risk * 1.15))

    contributing: list[str] = []
    pair_hits = 0
    # Strong-pair bonuses
    for i, a in enumerate(unique_types):
        for b in unique_types[i + 1:]:
            if (a, b) in STRONG_PAIRS:
                pair_hits += 1
    if pair_hits >= 1:
        combined += ESCALATION_BONUS["PAIR"]
        contributing.append("Strong indicator pair co-occurred (e.g. scam message + phishing URL)")
    if pair_hits >= 2 or len(unique_types) >= 3:
        combined += ESCALATION_BONUS["TRIPLE"]
        contributing.append("Multiple independent threat signals in the same time window")

    # Host linkage bonus
    hosts = [n["host"] for n in risky if n.get("host")]
    if len(hosts) >= 2 and len(set(hosts)) < len(hosts):
        combined += ESCALATION_BONUS["HOST_LINK"]
        contributing.append("The same host appears across multiple events")

    # Window check: events too far apart in time are downgraded
    times = sorted(n["detected_at"] for n in risky)
    if len(times) >= 2 and (times[-1] - times[0]) > timedelta(minutes=WINDOW_MINUTES * 4):
        contributing.append("Events are spread over a long time window — correlation confidence reduced")
        combined = int(combined * 0.85)

    combined = min(100, max(0, combined))
    severity = severity_for_score(combined)

    explanation = _explain(unique_types, combined, contributing)
    return {"chain_types": unique_types, "combined_risk": combined,
            "severity": severity, "explanation": explanation,
            "contributing_signals": contributing or ["Signals were considered individually"],
            "event_count": len(risky)}


def _explain(types: list[str], risk: int, signals: list[str]) -> str:
    if not types:
        return "No correlated threat activity."
    step_map = {
        "SMS_SCAM": "a scam text message", "MESSAGE_SCAM": "a scam message",
        "QR_PHISHING": "a malicious QR code", "URL_PHISHING": "a phishing URL",
        "URL_SUSPICIOUS": "a suspicious URL", "SUSPICIOUS_DOMAIN": "a suspicious domain",
        "REDIRECT_ANOMALY": "a suspicious redirect", "LOGIN_PAGE_RISK": "fake login page indicators",
        "FILE_RISKY": "a risky file", "APP_RISKY": "an app with high-risk permissions",
        "NETWORK_ANOMALY": "anomalous network activity",
    }
    steps = [f"{i + 1}. {step_map.get(t, t)}" for i, t in enumerate(types)]
    chain_text = " → ".join(step_map.get(t, t) for t in types)
    body = (f"Correlated attack chain detected: {chain_text}. "
            f"Combined risk {risk}/100 ({severity_for_score(risk)}). ")
    if len(types) >= 3:
        body += ("Multiple independent signals point to the same campaign — "
                 "this is a high-confidence attack chain. ")
    elif len(types) == 2:
        body += "Two related signals suggest a coordinated attempt. "
    body += "Steps: " + " ".join(steps)
    if signals:
        body += " Contributing: " + "; ".join(signals)
    return body


def record_event(db: Session, device_id: str | None, scan_id: str | None,
                 event_type: str, severity: str, risk_score: int,
                 evidence: dict) -> ThreatEvent:
    """Persist one structured security event (minimal evidence only)."""
    ev = ThreatEvent(device_id=device_id, scan_id=scan_id, event_type=event_type,
                     severity=severity, risk_score=risk_score,
                     evidence={"detail": str(evidence.get("detail", ""))[:200],
                               **{k: v for k, v in evidence.items()
                                  if k in ("host", "label", "payload_type")}})
    db.add(ev)
    db.flush()
    return ev


def maybe_build_chain(db: Session, device_id: str | None,
                      current_event: ThreatEvent) -> dict | None:
    """After recording an event, check whether it completes a chain with
    recent prior events for the same device. Persists a ThreatChain when found."""
    window_start = datetime.now(UTC) - timedelta(minutes=WINDOW_MINUTES)
    recent = (db.query(ThreatEvent)
                .filter(ThreatEvent.device_id == device_id,
                        ThreatEvent.detected_at >= window_start)
                .order_by(ThreatEvent.detected_at.asc())
                .limit(20).all())
    if len(recent) < 2:
        return None

    assessment = correlate_events(recent)
    types = assessment.get("chain_types", [])
    if len(types) >= 2 and assessment["combined_risk"] >= 50:
        chain = ThreatChain(device_id=device_id, chain_types=types,
                            combined_risk=assessment["combined_risk"],
                            severity=assessment["severity"],
                            explanation=assessment["explanation"])
        db.add(chain)
        db.flush()
        for ev in recent:
            ev.chain_id = chain.id
        logger.info("Threat chain built: %s (risk %d)", types, assessment["combined_risk"])
        return assessment
    return None


def recent_chains(db: Session, device_id: str | None, limit: int = 20) -> list[ThreatChain]:
    q = db.query(ThreatChain)
    if device_id:
        q = q.filter(ThreatChain.device_id == device_id)
    return q.order_by(ThreatChain.created_at.desc()).limit(limit).all()
