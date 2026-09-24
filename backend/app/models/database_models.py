"""SQLAlchemy database models (privacy-first: raw content stored only when enabled)."""
from datetime import UTC, datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text)

from app.database.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    devices = __import__("sqlalchemy").orm.relationship("Device", back_populates="user")


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_id = Column(String(128), index=True)  # client-generated anonymous UUID
    model = Column(String(128), nullable=True)
    os_version = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    user = __import__("sqlalchemy").orm.relationship("User", back_populates="devices")


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), unique=True, index=True)
    device_id = Column(String(128), index=True, nullable=True)
    type = Column(String(32), nullable=False)  # SMS | URL | FILE | QR | APP | NETWORK
    classification = Column(String(32))        # SAFE | SPAM | SCAM | PHISHING | ...
    risk_score = Column(Integer, default=0)
    severity = Column(String(16), default="SAFE")
    confidence = Column(Float, default=0.0)
    indicators = Column(JSON, default=list)
    detection_methods = Column(JSON, default=list)
    recommendation = Column(Text, default="")
    # Privacy: raw analyzed content stored only when STORE_RAW_CONTENT=true
    raw_content = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    events = __import__("sqlalchemy").orm.relationship("ThreatEvent", back_populates="scan")


class MessageRecord(Base):
    """Feature summary of analyzed messages — never raw SMS by default."""
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), index=True)
    length = Column(Integer, default=0)
    url_count = Column(Integer, default=0)
    urgency_score = Column(Integer, default=0)
    label = Column(String(32))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class UrlRecord(Base):
    __tablename__ = "urls"
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), index=True)
    url_hash = Column(String(64), index=True)  # SHA-256, not the raw URL
    host = Column(String(255), index=True)
    label = Column(String(32))
    probability = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class FileRecord(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), index=True)
    sha256 = Column(String(64), index=True)
    filename = Column(String(255))
    mime_type = Column(String(128))
    size_bytes = Column(Integer, default=0)
    label = Column(String(32))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ThreatEvent(Base):
    """Atomic detection events used by the correlation engine."""
    __tablename__ = "threat_events"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(128), index=True, nullable=True)
    scan_id = Column(String(64), ForeignKey("scan_results.scan_id"), nullable=True)
    event_type = Column(String(48), nullable=False)  # SMS_SCAM, URL_PHISHING, ...
    severity = Column(String(16), default="LOW")
    risk_score = Column(Integer, default=0)
    # Minimal evidence only — no raw content
    evidence = Column(JSON, default=dict)  # e.g. {"host": "example.xyz", "label": "PHISHING"}
    detected_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    scan = __import__("sqlalchemy").orm.relationship("ScanResult", back_populates="events")
    chain_id = Column(Integer, ForeignKey("threat_chains.id"), nullable=True)
    chain = __import__("sqlalchemy").orm.relationship("ThreatChain", back_populates="events")


class ThreatChain(Base):
    """Correlated multi-event attack chain."""
    __tablename__ = "threat_chains"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(128), index=True, nullable=True)
    chain_types = Column(JSON, default=list)   # ordered event types
    combined_risk = Column(Integer, default=0)
    severity = Column(String(16), default="LOW")
    explanation = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    events = __import__("sqlalchemy").orm.relationship("ThreatEvent", back_populates="chain")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(128), index=True, nullable=True)
    title = Column(String(255))
    body = Column(Text)
    severity = Column(String(16), default="LOW")
    acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class AppSecurityResult(Base):
    __tablename__ = "app_security_results"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(128), index=True, nullable=True)
    package_name = Column(String(255))
    app_label = Column(String(32))  # SAFE | CAUTION | RISKY
    risk_score = Column(Integer, default=0)
    sensitive_permissions = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class NetworkAnomaly(Base):
    __tablename__ = "network_anomalies"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(128), index=True, nullable=True)
    verdict = Column(String(16))  # NORMAL | SUSPICIOUS | ANOMALOUS
    anomaly_score = Column(Float, default=0.0)
    destinations = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow)
