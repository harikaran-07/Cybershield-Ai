"""File analysis endpoint — POST /api/v1/analyze/file (multipart upload).

Files are hashed and statically inspected. Never executed, never installed.
The raw file is NOT persisted — only name, size, hash and indicators.
"""
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import max_body_guard
from app.database.database import get_db
from app.models.schemas import AnalysisResponse

router = APIRouter(tags=["analyze"])


@router.post("/analyze/file", response_model=AnalysisResponse)
async def analyze_file(db: Session = Depends(get_db),
                       file: UploadFile = File(...),
                       device_id: str | None = Form(default=None)) -> AnalysisResponse:
    """Static file analysis. Max size limited by MAX_BODY_BYTES (default 8 MiB)."""
    filename = file.filename or "unnamed"
    try:
        data = await file.read(settings.MAX_BODY_BYTES + 1)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not read uploaded file") from exc
    if len(data) > settings.MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size")
    if len(data) == 0:
        raise HTTPException(status_code=422, detail="Uploaded file is empty")

    try:
        from app.services.scan_service import analyze_file_scan
        result = analyze_file_scan(db, filename, data, file.content_type, device_id)
        return AnalysisResponse(**{k: v for k, v in result.items()
                                   if k in AnalysisResponse.model_fields})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="File analysis failed — please retry") from exc
