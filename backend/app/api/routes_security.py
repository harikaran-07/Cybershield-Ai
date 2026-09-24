"""Security endpoints — app permissions and network anomaly analysis."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.schemas import (AppSecurityRequest, AppSecurityOut,
                                NetworkRequest, NetworkAnalysisOut)

router = APIRouter(tags=["security"])


@router.post("/analyze/app")
def analyze_app(req: AppSecurityRequest, db: Session = Depends(get_db)) -> dict:
    """Permission-risk analysis of client-reported installed apps."""
    try:
        from app.services.scan_service import analyze_app_security
        return analyze_app_security(db, req.device_id,
                                    [a.model_dump() for a in req.apps])
    except Exception as exc:
        raise HTTPException(status_code=500, detail="App security analysis failed") from exc


@router.post("/analyze/network", response_model=NetworkAnalysisOut)
def analyze_network(req: NetworkRequest, db: Session = Depends(get_db)) -> NetworkAnalysisOut:
    """Privacy-preserving metadata analysis. Contents are never sent/stored."""
    try:
        from app.services.scan_service import analyze_network_scan
        result = analyze_network_scan(db, req.device_id,
                                      [s.model_dump() for s in req.stats],
                                      req.window_minutes)
        return NetworkAnalysisOut(verdict=result["verdict"],
                                  anomaly_score=result["anomaly_score"],
                                  flagged_destinations=result["flagged_destinations"],
                                  notes=result["notes"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Network analysis failed") from exc
