"""Pydantic request/response models — the API contract."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Shared values
# ---------------------------------------------------------------------------
SEVERITIES = ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def severity_for_score(score: int) -> str:
    """App-specific calibration thresholds (NOT universal standards)."""
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 25:
        return "LOW"
    return "SAFE"


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class MessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    device_id: str | None = Field(default=None, max_length=128)

    @field_validator("text")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Message text must not be blank")
        return v


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    device_id: str | None = Field(default=None, max_length=128)


class QrRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=4096)
    qr_format: str = Field(default="QR_CODE", max_length=32)
    device_id: str | None = Field(default=None, max_length=128)


class FileRequest(BaseModel):
    """Metadata-only file analysis; bytes uploaded via multipart at the route."""
    filename: str = Field(..., max_length=255)
    mime_type: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=128)


class AppInfo(BaseModel):
    # NOTE: never hard-reject the whole request for oversized per-app data.
    # Real devices contain stock packages (e.g. com.android.shell) that declare
    # hundreds of permissions — truncating is safer than failing the entire
    # 422-prone device scan.
    package_name: str = Field(..., max_length=255)
    app_name: str | None = Field(default=None, max_length=255)
    permissions: list[str] = Field(default_factory=list)

    @field_validator("permissions", mode="before")
    @classmethod
    def _cap_permissions(cls, v):
        if not isinstance(v, list):
            return v
        if len(v) > 200:
            return v[:200]  # analysis stays valid; excess permissions dropped
        return v

    is_system_app: bool = False
    from_unknown_source: bool | None = None
    accessibility_enabled: bool | None = None
    # Framework packages can report huge internal targetSdk values (e.g. 10000);
    # clamp rather than reject the whole device scan.
    target_sdk: int | None = Field(default=None, ge=1, le=10000)


class AppSecurityRequest(BaseModel):
    device_id: str | None = Field(default=None, max_length=128)
    apps: list[AppInfo] = Field(..., min_length=1, max_length=500)


class NetworkStats(BaseModel):
    destination: str = Field(..., max_length=255)  # hostname or IP — metadata only
    connection_count: int = Field(default=0, ge=0)
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    distinct_ports: int = Field(default=0, ge=0)


class NetworkRequest(BaseModel):
    device_id: str | None = Field(default=None, max_length=128)
    window_minutes: int = Field(default=15, ge=1, le=1440)
    stats: list[NetworkStats] = Field(..., min_length=1, max_length=1000)


class ExplainRequest(BaseModel):
    scan_id: str | None = Field(default=None, max_length=64)
    threat_type: str = Field(..., max_length=64)
    risk_score: int = Field(..., ge=0, le=100)
    severity: str = Field(..., max_length=16)
    indicators: list[str] = Field(default_factory=list, max_length=50)
    question: str | None = Field(default=None, max_length=2000)


class ChainLink(BaseModel):
    event_type: str
    scan_id: str | None = None
    risk_score: int = 0
    detail: str = ""


class ChainRequest(BaseModel):
    """Explicit client-supplied events to correlate (also used internally)."""
    device_id: str | None = Field(default=None, max_length=128)
    events: list[ChainLink] = Field(..., min_length=1, max_length=20)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
class AnalysisResponse(BaseModel):
    """Consistent response envelope for all analyze endpoints."""
    scan_id: str
    type: str
    risk_score: int
    severity: str
    classification: str
    confidence: float
    indicators: list[str] = []
    detection_methods: list[str] = []
    recommendation: str = ""
    ai_explanation: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ThreatOut(BaseModel):
    scan_id: str
    type: str
    classification: str
    risk_score: int
    severity: str
    confidence: float
    indicators: list[str] = []
    detection_methods: list[str] = []
    recommendation: str = ""
    created_at: datetime | None = None


class ThreatListResponse(BaseModel):
    total: int
    threats: list[ThreatOut]


class ThreatDetailResponse(AnalysisResponse):
    timeline: list[dict[str, Any]] = []
    correlated_chain: dict[str, Any] | None = None


class ChainResponse(BaseModel):
    chain_id: str | None = None
    events: list[ChainLink]
    combined_risk: int
    severity: str
    chain_types: list[str]
    explanation: str
    contributing_signals: list[str]


class DashboardResponse(BaseModel):
    total_scans: int
    safe_count: int
    threats_detected: int
    high_risk_count: int
    highest_risk: ThreatOut | None = None
    lowest_risk: ThreatOut | None = None
    most_common_threat: str | None = None
    threats_by_type: dict[str, int] = Field(default_factory=dict)
    threats_by_severity: dict[str, int] = Field(default_factory=dict)
    scan_trend: list[dict[str, Any]] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    nlp_model: str
    url_model: str
    anomaly_model: str
    llm: str
    llm_model: str | None = None


class AiStatusResponse(BaseModel):
    llm_available: bool
    model: str
    base_url: str
    explanation_enabled: bool


class FileAnalysisOut(BaseModel):
    filename: str
    mime_type: str | None = None
    size_bytes: int
    sha256: str
    extension_mismatch: bool = False
    double_extension: bool = False


class AppPermissionOut(BaseModel):
    permission: str
    category: str  # LOW | MEDIUM | HIGH


class AppSecurityOut(BaseModel):
    package_name: str
    app_name: str | None = None
    risk_score: int
    label: str  # SAFE | CAUTION | RISKY
    permissions: list[AppPermissionOut]
    notes: list[str] = []


class NetworkAnalysisOut(BaseModel):
    verdict: str  # NORMAL | SUSPICIOUS | ANOMALOUS
    anomaly_score: float
    flagged_destinations: list[str] = []
    notes: list[str] = []
