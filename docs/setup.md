# Setup Guide

## 1. Backend (FastAPI)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    |    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # edit values; never commit .env
uvicorn app.main:app --reload --port 8000
```

Verify: `http://localhost:8000/api/v1/health`

Development uses SQLite by default. For PostgreSQL use Docker (Step 3) and set
`DATABASE_URL=postgresql+psycopg://cybershield:change-me@localhost:5432/cybershield`.

## 2. Android app

```bash
cd android
# Open in Android Studio (Ladybug+), let Gradle sync, then Run
```

- Minimum SDK 26 (Android 8.0), target 34
- The emulator reaches a localhost backend via `http://10.0.2.2:8000/` (default)
- A physical device: use your machine's LAN IP in
  `app/build.gradle.kts → buildConfigField API_BASE_URL`
- Production: use HTTPS and change the release `API_BASE_URL`

## 3. PostgreSQL via Docker

```bash
docker compose up -d db       # from the project root
# schema.sql is applied automatically on first start
```

## 4. Ollama (local LLM)

```bash
# Install from https://ollama.com, then:
ollama pull qwen2.5:1.5b      # small model for modest hardware
# alternatives: qwen2.5:0.5b (very low RAM) | qwen2.5:7b (needs ~8GB+)
ollama serve                  # usually runs automatically
```

Check: `curl http://localhost:11434/api/tags`

## 5. ML models (optional but recommended)

Models are NOT bundled — train them on data you are licensed to use:

```bash
cd backend
python ../scripts/train_models.py --url --train ../data/url_train.csv
python ../scripts/train_models.py --roberta --train ../data/sms_train.csv
python ../scripts/train_models.py --anomaly --train ../data/network_train.csv
```

Artifacts land in the paths configured in `.env`
(`MODEL_PATH`, `URL_MODEL_PATH`, `ANOMALY_MODEL_PATH`).
Until then the services run transparent fallbacks and `/health` reports
`fallback` honestly. Real evaluation metrics are printed during training and
saved next to each model (`EVALUATION.txt`).

## 6. Running the tests

```bash
cd backend
.venv/Scripts/python -m pytest tests/ -q     # Windows
# or: python -m pytest tests/ -q
```

## 7. Full stack (docker compose)

```bash
docker compose up --build
# backend: http://localhost:8000 · db: localhost:5432
# Ollama stays on the host (OLLAMA_BASE_URL points at host.docker.internal)
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Android can't reach backend | Emulator: use 10.0.2.2. Device: use LAN IP + same Wi-Fi |
| `llm: unavailable` in /health | Start Ollama and `ollama pull <model>`; check OLLAMA_BASE_URL |
| App list empty in Security tab | Android 11+ package visibility — the UI explains this |
| File scan says 413 | File exceeds MAX_BODY_BYTES (default 8 MiB) |
