"""URL analysis endpoint — POST /api/v1/analyze/url."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.schemas import AnalysisResponse, UrlRequest

router = APIRouter(tags=["analyze"])


@router.post("/analyze/url", response_model=AnalysisResponse)
def analyze_url(req: UrlRequest, db: Session = Depends(get_db)) -> AnalysisResponse:
    """Static URL analysis. The URL is never fetched or visited."""
    url = req.url.strip()
    if not (url.startswith("http://") or url.startswith("https://") or "." in url):
        raise HTTPException(status_code=422, detail="Invalid URL format")
    try:
        from app.services.scan_service import analyze_url_scan
        result = analyze_url_scan(db, url, req.device_id)
        return AnalysisResponse(**{k: v for k, v in result.items()
                                   if k in AnalysisResponse.model_fields})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="URL analysis failed — please retry") from exc
