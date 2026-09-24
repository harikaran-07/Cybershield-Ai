"""AI endpoints — explanation, chat assistant, threat chains."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.schemas import (AiStatusResponse, ChainLink, ChainRequest,
                                ChainResponse, ExplainRequest, ThreatOut)
from app.services import llm_service
from app.services.threat_correlation import correlate_events, recent_chains

router = APIRouter(tags=["ai"])


@router.post("/ai/explain")
def explain(req: ExplainRequest) -> dict:
    """Explain a detection result using the local LLM (evidence-grounded only)."""
    out = llm_service.explain_threat(req.threat_type, req.risk_score,
                                     req.severity, req.indicators, req.question)
    return out


@router.post("/ai/chat")
def chat(payload: dict) -> dict:
    """AI Security Assistant — grounded in optional scan context."""
    question = str(payload.get("question", ""))[:2000]
    context = payload.get("context") if isinstance(payload.get("context"), dict) else None
    return llm_service.chat_response(question, context)


@router.get("/ai/status", response_model=AiStatusResponse)
def ai_status() -> AiStatusResponse:
    from app.core.config import settings
    _status, model = llm_service.llm_status()
    return AiStatusResponse(llm_available=llm_service.llm_available(),
                            model=model or "none",
                            base_url=(settings.LLM_BASE_URL if settings.LLM_API_KEY
                                      else settings.OLLAMA_BASE_URL),
                            explanation_enabled=settings.LLM_EXPLANATIONS_ENABLED)


@router.post("/threats/chain", response_model=ChainResponse)
def build_chain(req: ChainRequest) -> ChainResponse:
    """Correlate explicitly supplied events into an attack chain."""
    if not req.events:
        raise HTTPException(422, "At least one event is required")
    assessment = correlate_events(req.events)
    return ChainResponse(chain_id=None,
                         events=req.events,
                         combined_risk=assessment["combined_risk"],
                         severity=assessment["severity"],
                         chain_types=assessment["chain_types"],
                         explanation=assessment["explanation"],
                         contributing_signals=assessment["contributing_signals"])


@router.get("/threats/chains")
def list_chains(device_id: str | None = Query(default=None),
                db: Session = Depends(get_db)) -> list[dict]:
    chains = recent_chains(db, device_id)
    return [{"id": c.id, "chain_types": c.chain_types,
             "combined_risk": c.combined_risk, "severity": c.severity,
             "explanation": c.explanation, "created_at": str(c.created_at)}
            for c in chains]
