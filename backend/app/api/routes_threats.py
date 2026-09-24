"""Threat history and dashboard endpoints."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.database_models import ScanResult, ThreatEvent
from app.models.schemas import ThreatDetailResponse, ThreatListResponse, ThreatOut

router = APIRouter(tags=["threats"])


def _to_threat_out(s: ScanResult) -> ThreatOut:
    return ThreatOut(scan_id=s.scan_id, type=s.type, classification=s.classification or "SAFE",
                     risk_score=s.risk_score or 0, severity=s.severity or "SAFE",
                     confidence=s.confidence or 0.0, indicators=s.indicators or [],
                     detection_methods=s.detection_methods or [],
                     recommendation=s.recommendation or "", created_at=s.created_at)


@router.get("/threats", response_model=ThreatListResponse)
def list_threats(db: Session = Depends(get_db),
                 device_id: str | None = Query(default=None),
                 severity: str | None = Query(default=None),
                 threat_type: str | None = Query(default=None),
                 min_score: int = Query(default=0, ge=0, le=100),
                 limit: int = Query(default=50, ge=1, le=200),
                 offset: int = Query(default=0, ge=0)) -> ThreatListResponse:
    """Threat history with filters: severity, type, minimum score, date window."""
    q = db.query(ScanResult)
    if device_id:
        q = q.filter(ScanResult.device_id == device_id)
    if severity:
        q = q.filter(ScanResult.severity == severity.upper())
    if threat_type:
        q = q.filter(ScanResult.type == threat_type.upper())
    q = q.filter(ScanResult.risk_score >= min_score)
    total = q.count()
    rows = (q.order_by(ScanResult.created_at.desc())
             .offset(offset).limit(limit).all())
    return ThreatListResponse(total=total, threats=[_to_threat_out(r) for r in rows])


@router.get("/threats/{scan_id}", response_model=ThreatDetailResponse)
def threat_detail(scan_id: str, db: Session = Depends(get_db)) -> ThreatDetailResponse:
    """Full threat detail including event timeline and correlated chain."""
    s = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if s is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    events = (db.query(ThreatEvent)
                .filter((ThreatEvent.scan_id == scan_id) |
                        ((ThreatEvent.device_id == s.device_id) &
                         (ThreatEvent.detected_at >=
                          (s.created_at or datetime.utcnow()))))
                .order_by(ThreatEvent.detected_at.asc())
                .limit(50).all())

    timeline = [{"time": str(e.detected_at), "event_type": e.event_type,
                 "severity": e.severity, "risk_score": e.risk_score,
                 "detail": (e.evidence or {}).get("detail", "")}
                for e in events]

    correlated = None
    chain_ids = [e.chain_id for e in events if e.chain_id]
    if chain_ids:
        from app.models.database_models import ThreatChain
        chain = db.query(ThreatChain).filter(ThreatChain.id == chain_ids[-1]).first()
        if chain:
            correlated = {"chain_types": chain.chain_types,
                          "combined_risk": chain.combined_risk,
                          "severity": chain.severity,
                          "explanation": chain.explanation}

    base = _to_threat_out(s).model_dump()
    detail = ThreatDetailResponse(
        **base,
        ai_explanation=None,
        timeline=timeline,
        correlated_chain=correlated,
    )
    return detail


@router.get("/dashboard")
def dashboard(device_id: str | None = Query(default=None),
              db: Session = Depends(get_db)) -> dict:
    """Aggregated statistics powering the Android dashboard."""
    q = db.query(ScanResult)
    if device_id:
        q = q.filter(ScanResult.device_id == device_id)
    total = q.count()
    safe = q.filter(ScanResult.risk_score < 25).count()
    threats = q.filter(ScanResult.risk_score >= 25).count()
    high = q.filter(ScanResult.risk_score >= 75).count()

    highest = q.order_by(ScanResult.risk_score.desc()).first()
    lowest = q.order_by(ScanResult.risk_score.asc()).first()

    # NOTE: every aggregate below MUST honor the device filter — otherwise one
    # device's dashboard would include other devices' scan statistics.
    def _dev(qq):
        return qq.filter(ScanResult.device_id == device_id) if device_id else qq

    by_type = dict((_dev(db.query(ScanResult.type, func.count(ScanResult.id)))
                    .group_by(ScanResult.type).all()))
    by_sev = dict((_dev(db.query(ScanResult.severity, func.count(ScanResult.id)))
                   .group_by(ScanResult.severity).all()))
    most_common = (_dev(db.query(ScanResult.classification, func.count(ScanResult.id))
                        .filter(ScanResult.risk_score >= 25))
                   .group_by(ScanResult.classification)
                   .order_by(func.count(ScanResult.id).desc()).first())

    trend_rows = (_dev(db.query(func.date(ScanResult.created_at), func.count(ScanResult.id)))
                  .group_by(func.date(ScanResult.created_at))
                  .order_by(func.date(ScanResult.created_at).desc())
                  .limit(14).all())

    return {
        "total_scans": total,
        "safe_count": safe,
        "threats_detected": threats,
        "high_risk_count": high,
        "highest_risk": _to_threat_out(highest).model_dump() if highest else None,
        "lowest_risk": _to_threat_out(lowest).model_dump() if lowest else None,
        "most_common_threat": most_common[0] if most_common else None,
        "threats_by_type": by_type,
        "threats_by_severity": by_sev,
        "scan_trend": [{"date": str(d), "count": c} for d, c in reversed(trend_rows)],
    }


@router.delete("/threats/history")
def delete_history(device_id: str | None = Query(default=None),
                   db: Session = Depends(get_db)) -> dict:
    """Delete scan history (privacy control). Events/chains included.

    Deletion order respects foreign keys: threat_events references BOTH
    scan_results.scan_id and threat_chains.id, so events must be deleted
    first, then chains, then scans. (SQLite tolerated the wrong order
    because FK enforcement is off by default; PostgreSQL rejects it.)
    """
    from app.models.database_models import ThreatChain
    sq = db.query(ScanResult)
    eq = db.query(ThreatEvent)
    cq = db.query(ThreatChain)
    if device_id:
        sq = sq.filter(ScanResult.device_id == device_id)
        eq = eq.filter(ThreatEvent.device_id == device_id)
        cq = cq.filter(ThreatChain.device_id == device_id)
    # 1) events reference scans AND chains — always first
    events_deleted = eq.delete(synchronize_session=False)
    # 2) chains: their referencing events are now gone
    chains_deleted = cq.delete(synchronize_session=False)
    # 3) scans last
    scans_deleted = sq.delete(synchronize_session=False)
    db.commit()
    return {"deleted_scans": scans_deleted, "deleted_events": events_deleted,
            "deleted_chains": chains_deleted, "status": "history cleared"}
