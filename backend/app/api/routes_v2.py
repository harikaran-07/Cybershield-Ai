"""v2 API endpoints — /api/url/analyze, /api/text/analyze, /api/file/analyze,
/api/apk/analyze, /api/threat/correlate, /api/security/events, /api/security/summary.

These are convenience aliases/combos over the v1 detection services. The
detection logic is identical; v1 /api/v1/* endpoints remain supported.
"""
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.models.database_models import ScanResult, ThreatEvent
from app.models.schemas import severity_for_score
from app.services import scan_service
from app.services.apk_service import analyze_apk
from app.services.risk_engine import RiskInputs, compute_risk, explain_risk
from app.services.threat_correlation import correlate_events

router = APIRouter(prefix="/api", tags=["v2"])


@router.post("/url/analyze")
def url_analyze(url: str = Query(..., max_length=2048),
                device_id: str | None = Query(default=None),
                db: Session = Depends(get_db)) -> dict:
    if not (url.strip().startswith("http") or "." in url):
        raise HTTPException(422, "Invalid URL format")
    return scan_service.analyze_url_scan(db, url.strip(), device_id)


@router.post("/text/analyze")
def text_analyze(payload: dict, db: Session = Depends(get_db)) -> dict:
    text = str(payload.get("text", ""))[:settings.MAX_TEXT_CHARS]
    if not text.strip():
        raise HTTPException(422, "text must not be blank")
    device_id = payload.get("device_id")
    if isinstance(device_id, str) and len(device_id) > 128:
        device_id = device_id[:128]
    return scan_service.analyze_message(db, text, device_id)


@router.post("/file/analyze")
async def file_analyze(db: Session = Depends(get_db),
                       file: UploadFile = File(...),
                       device_id: str | None = Form(default=None)) -> dict:
    data = await file.read(settings.MAX_BODY_BYTES + 1)
    if len(data) > settings.MAX_BODY_BYTES:
        raise HTTPException(413, "File exceeds maximum allowed size")
    if not data:
        raise HTTPException(422, "Uploaded file is empty")
    return scan_service.analyze_file_scan(db, file.filename or "unnamed", data,
                                          file.content_type, device_id)


@router.post("/apk/analyze")
async def apk_analyze(db: Session = Depends(get_db),
                      file: UploadFile = File(...),
                      device_id: str | None = Form(default=None)) -> dict:
    """Safe static APK analysis — never executes the package."""
    data = await file.read(settings.MAX_BODY_BYTES + 1)
    if len(data) > settings.MAX_BODY_BYTES:
        raise HTTPException(413, "APK exceeds maximum allowed size")
    if not data:
        raise HTTPException(422, "Uploaded file is empty")
    name = file.filename or "app.apk"
    if not name.lower().endswith(".apk"):
        raise HTTPException(422, "Endpoint expects an .apk file")

    result = analyze_apk(name, data)
    # Persist as a scan + event so it appears in history/summary
    from app.services.threat_correlation import record_event, maybe_build_chain
    scan_id = scan_service._new_scan_id()
    from app.models.database_models import ScanResult
    db.add(ScanResult(scan_id=scan_id, device_id=device_id, type="APK",
                      classification=result["classification"],
                      risk_score=result["risk_score"], severity=result["severity"],
                      confidence=0.6, indicators=result["indicators"],
                      detection_methods=result["detection_methods"],
                      recommendation=result["recommendation"]))
    db.flush()
    ev = record_event(db, device_id, scan_id,
                      "APK_RISKY" if result["classification"] != "SAFE" else "APK_SCANNED",
                      result["severity"], result["risk_score"],
                      {"detail": result["filename"], "label": result["classification"]})
    maybe_build_chain(db, device_id, ev)

    from app.models.schemas import AnalysisResponse
    resp = AnalysisResponse(
        scan_id=scan_id, type="APK",
        risk_score=result["risk_score"], severity=result["severity"],
        classification=result["classification"], confidence=0.6,
        indicators=result["indicators"],
        detection_methods=result["detection_methods"],
        recommendation=result["recommendation"])
    return resp.model_dump() | {
        "sha256": result["sha256"], "permissions": result["permissions"],
        "dangerous_permissions": result["dangerous_permissions"],
        "entry_count": result["entry_count"], "dex_count": result["dex_count"],
        "note": result["note"]}


@router.post("/threat/correlate")
def threat_correlate(payload: dict, db: Session = Depends(get_db)) -> dict:
    events = payload.get("events", [])
    if not isinstance(events, list) or not events:
        raise HTTPException(422, "events list required")
    from app.models.schemas import ChainLink
    links: list[ChainLink] = []
    for e in events[:20]:
        if not isinstance(e, dict) or "event_type" not in e:
            raise HTTPException(422, "each event needs event_type")
        links.append(ChainLink(
            event_type=str(e["event_type"])[:48],
            risk_score=int(e.get("risk_score", 0)),
            detail=str(e.get("detail", ""))[:200]))
    return correlate_events(links)


@router.get("/security/events")
def security_events(device_id: str | None = Query(default=None),
                    severity: str | None = Query(default=None),
                    category: str | None = Query(default=None),
                    limit: int = Query(default=50, ge=1, le=200),
                    db: Session = Depends(get_db)) -> dict:
    """Event history for the Security Console (metadata only)."""
    q = db.query(ThreatEvent)
    if device_id:
        q = q.filter(ThreatEvent.device_id == device_id)
    if severity:
        q = q.filter(ThreatEvent.severity == severity.upper())
    if category:
        q = q.filter(ThreatEvent.event_type.contains(category.upper()))
    rows = q.order_by(ThreatEvent.detected_at.desc()).limit(limit).all()
    return {"total": len(rows), "events": [
        {"id": r.id, "time": str(r.detected_at), "type": r.event_type,
         "severity": r.severity, "risk": r.risk_score,
         "detail": (r.evidence or {}).get("detail", "")} for r in rows]}


@router.get("/security/summary")
def security_summary(device_id: str | None = Query(default=None),
                     db: Session = Depends(get_db)) -> dict:
    """Aggregate summary powering the Security Console dashboard."""
    q = db.query(ScanResult)
    eq = db.query(ThreatEvent)
    if device_id:
        q = q.filter(ScanResult.device_id == device_id)
        eq = eq.filter(ThreatEvent.device_id == device_id)
    total = q.count()
    by_type = dict(q.with_entities(ScanResult.type, func.count(ScanResult.id))
                   .group_by(ScanResult.type).all())
    by_sev = dict(q.with_entities(ScanResult.severity, func.count(ScanResult.id))
                  .group_by(ScanResult.severity).all())
    high = sum(c for s, c in by_sev.items() if s in ("HIGH", "CRITICAL"))
    threats = sum(c for s, c in by_sev.items() if s not in ("SAFE", "LOW"))
    score = max(25, min(100, 100 - high * 6 - (threats - high) * 2))
    return {
        "security_score": score,
        "status": "Protected" if high == 0 else "Attention needed",
        "total_scans": total,
        "threats": threats,
        "high_risk": high,
        "by_type": by_type,
        "by_severity": by_sev,
        "monitoring_note": ("This summary covers items analyzed through the backend. "
                            "Phone-side background monitoring happens in the Android app."),
    }
