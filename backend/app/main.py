"""FastAPI application factory and route registration."""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text as sql_text

from app.core.config import settings
from app.database.database import engine, init_db
from app.api import (routes_ai, routes_file, routes_message, routes_qr,
                     routes_security, routes_threats, routes_url, routes_v2)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Startup: create tables (Alembic handles production migrations)
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.VERSION,
        description="AI-Powered Personal Cyber Threat Detection & Protection — defensive only.",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS — configurable via CORS_ORIGINS env ("*" for dev; lock down in production)
    origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Request body size guard
    @app.middleware("http")
    async def body_size_guard(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > settings.MAX_BODY_BYTES:
            return JSONResponse(status_code=413,
                                content={"detail": "Request body too large"})
        return await call_next(request)

    app.include_router(routes_message.router, prefix="/api/v1")
    app.include_router(routes_url.router, prefix="/api/v1")
    app.include_router(routes_qr.router, prefix="/api/v1")
    app.include_router(routes_file.router, prefix="/api/v1")
    app.include_router(routes_security.router, prefix="/api/v1")
    app.include_router(routes_ai.router, prefix="/api/v1")
    app.include_router(routes_threats.router, prefix="/api/v1")
    app.include_router(routes_v2.router)

    # Idempotent schema creation so tables exist even without lifespan events
    # (production deployments should manage schema via Alembic migrations)
    init_db()

    @app.get("/api/v1/health", response_model=None)
    def health() -> dict:
        """Honest component status — models are never faked as loaded."""
        from app.services import llm_service, nlp_service, network_service, url_service
        db_status = "connected"
        try:
            with engine.connect() as conn:
                conn.execute(sql_text("SELECT 1"))
        except Exception:
            db_status = "unavailable"
        llm_status, llm_model = llm_service.llm_status()
        return {
            "status": "ok" if db_status == "connected" else "degraded",
            "version": settings.VERSION,
            "database": db_status,
            "nlp_model": nlp_service.nlp_model_status(),
            "url_model": url_service.url_model_status(),
            "anomaly_model": network_service.anomaly_model_status(),
            "llm": llm_status,
            "llm_model": llm_model,
        }

    return app


app = create_app()
