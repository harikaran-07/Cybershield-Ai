"""Message analysis endpoint — POST /api/v1/analyze/message."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.security import max_body_guard
from app.database.database import get_db
from app.models.schemas import AnalysisResponse, MessageRequest

router = APIRouter(tags=["analyze"])


@router.post("/analyze/message", response_model=AnalysisResponse)
def analyze_message(req: MessageRequest, db: Session = Depends(get_db)) -> AnalysisResponse:
    """Analyze message/SMS/email text. URLs are extracted and analyzed too."""
    try:
        result = scan_service_analyze_message(db, req.text, req.device_id)
        return AnalysisResponse(**{k: v for k, v in result.items()
                                   if k in AnalysisResponse.model_fields})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Analysis failed — please retry") from exc


def scan_service_analyze_message(db: Session, text: str, device_id: str | None) -> dict:
    from app.services.scan_service import analyze_message
    return analyze_message(db, text, device_id)
