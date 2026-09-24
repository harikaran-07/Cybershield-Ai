"""Application configuration via environment variables (12-factor)."""
import logging
import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def resolve_model_path(raw: str) -> str:
    """Resolve a model path robustly across CWDs and deployment layouts.

    Trained artifacts live under backend/app/ml/<name>, but the server may be
    started from the repo root (uvicorn app.main:app), from backend/, or from a
    serverless bundle where relative defaults silently miss the directory. This
    resolver anchors relative paths to the backend/ package root and falls back
    to sibling candidates so a trained model is actually FOUND and loaded
    instead of the app reporting a permanent (misleading) "fallback" status.
    """
    p = Path(raw).expanduser()
    if p.is_absolute():
        return str(p)
    backend_root = Path(__file__).resolve().parents[2]  # .../backend
    candidates = [backend_root / p]
    # If given like "app/ml/roberta" from repo root, try backend-prefixed too
    if "backend" not in p.parts:
        candidates.append(backend_root.parent / "backend" / p)
    for c in candidates:
        if c.exists():
            return str(c)
    return str(backend_root / p)  # deterministic default for missing-path errors


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    APP_NAME: str = "CyberShield AI"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database (SQLite fallback keeps local dev friction-free; use PostgreSQL in production)
    DATABASE_URL: str = "sqlite:///./cybershield.db"

    # Ollama local LLM runtime (works on dev machines / VPS with Ollama installed)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:1.5b"
    # Hosted LLM — any OpenAI-compatible endpoint (OpenAI, Groq, Together, OpenRouter,
    # LM Studio...). Takes priority over Ollama when LLM_API_KEY is set. This is how
    # serverless deployments (Vercel) get REAL LLM explanations: Ollama cannot run there.
    LLM_API_KEY: str = ""  # set via environment; NEVER hardcode
    LLM_BASE_URL: str = "https://api.openai.com/v1"
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_EXPLANATIONS_ENABLED: bool = True
    LLM_TIMEOUT_SECONDS: int = 25

    # Server
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: str = "*"

    # ML model paths — place trained artifacts here (see docs/setup.md and scripts/train_models.py)
    # Relative paths are resolved against the backend/ package root (see resolve_model_path).
    MODEL_PATH: str = "app/ml/roberta"
    URL_MODEL_PATH: str = "app/ml/url_model"
    ANOMALY_MODEL_PATH: str = "app/ml/anomaly_model"

    # Risk engine weights (auto-normalized; tunable per deployment)
    WEIGHT_NLP: float = 0.30
    WEIGHT_URL: float = 0.30
    WEIGHT_RULES: float = 0.25
    WEIGHT_FILE: float = 0.15
    WEIGHT_APP: float = 0.10
    WEIGHT_NETWORK: float = 0.10
    WEIGHT_CORRELATION: float = 0.20

    # Security
    SECRET_KEY: str = "change-me-in-production"
    MAX_BODY_BYTES: int = 8 * 1024 * 1024  # 8 MiB upload cap
    MAX_TEXT_CHARS: int = 20_000

    # Privacy: store raw analyzed text/messages in DB. Default OFF (privacy-first).
    STORE_RAW_CONTENT: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

# Expose resolved, CWD-independent model paths for services/loaders.
MODEL_DIR = resolve_model_path(settings.MODEL_PATH)
URL_MODEL_DIR = resolve_model_path(settings.URL_MODEL_PATH)
ANOMALY_MODEL_DIR = resolve_model_path(settings.ANOMALY_MODEL_PATH)
# Lightweight trained classifier tier (TF-IDF + LogisticRegression) — see scripts/train_prod_nlp.py
NLP_PROD_MODEL_DIR = resolve_model_path("app/ml/nlp_prod")

# Import-time sanity: never crash startup, but make missing artifacts visible.
for _name, _d in (("MODEL_PATH", MODEL_DIR), ("URL_MODEL_PATH", URL_MODEL_DIR),
                  ("ANOMALY_MODEL_PATH", ANOMALY_MODEL_DIR),
                  ("NLP_PROD_MODEL_DIR", NLP_PROD_MODEL_DIR)):
    if not os.path.isdir(_d):
        logging.getLogger(__name__).info(
            "ML dir for %s not found at %s — service will report fallback until trained artifacts are placed there.",
            _name, _d)
