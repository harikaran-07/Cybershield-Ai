"""QR analysis endpoint — POST /api/v1/analyze/qr.

The Android client decodes the QR locally (ML Kit) and posts the string content.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.schemas import AnalysisResponse, QrRequest

router = APIRouter(tags=["analyze"])


@router.post("/analyze/qr", response_model=AnalysisResponse)
def analyze_qr(req: QrRequest, db: Session = Depends(get_db)) -> AnalysisResponse:
    """Triage decoded QR payload; URLs inside are routed to URL analysis."""
    if not req.content.strip():
        raise HTTPException(status_code=422, detail="QR content must not be empty")
    try:
        from app.services.scan_service import analyze_qr_scan
        result = analyze_qr_scan(db, req.content, req.qr_format, req.device_id)
        return AnalysisResponse(**{k: v for k, v in result.items()
                                   if k in AnalysisResponse.model_fields})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="QR analysis failed — please retry") from exc
