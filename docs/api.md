# API Reference

Base URL: `http://<host>:8000/api/v1` (use HTTPS in production)
Interactive docs: `/docs` (Swagger UI)

## Consistent response envelope

All `analyze/*` endpoints return `AnalysisResponse`:

```json
{
  "scan_id": "16-hex-id",
  "type": "URL",
  "risk_score": 88,
  "severity": "HIGH",
  "classification": "PHISHING",
  "confidence": 0.91,
  "indicators": ["Host is a raw IP address instead of a domain name"],
  "detection_methods": ["XGBoost", "Rule Engine"],
  "recommendation": "Do not open this link…",
  "ai_explanation": "What was detected: …",
  "details": { "risk_breakdown": { } }
}
```

## Analyze endpoints

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/analyze/message` | `{"text": "...", "device_id": "..."}` | RoBERTa + rules + URL extraction |
| POST | `/analyze/url` | `{"url": "https://..."}` | Static analysis only, never fetched |
| POST | `/analyze/qr` | `{"content": "...", "qr_format": "QR_CODE"}` | Content decoded client-side by ML Kit |
| POST | `/analyze/file` | multipart `file` + optional `device_id` | Max 8 MiB; hash + metadata only |
| POST | `/analyze/app` | `{"apps": [{package_name, permissions: [...]}]}` | Permission risk categorization |
| POST | `/analyze/network` | `{"window_minutes": 15, "stats": [{destination, connection_count, ...}]}` | Metadata only |

## History & dashboard

| Method | Path | Notes |
|---|---|---|
| GET | `/threats?severity=&threat_type=&min_score=&limit=&offset=` | Filtered history |
| GET | `/threats/{scan_id}` | Detail incl. timeline + correlated chain |
| GET | `/dashboard?device_id=` | Aggregate stats for charts |
| GET | `/threats/chains?device_id=` | Recent correlated chains |
| DELETE | `/threats/history?device_id=` | Delete history (privacy control) |

## AI endpoints

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/ai/explain` | `{"threat_type", "risk_score", "severity", "indicators"}` | Evidence-grounded explanation |
| POST | `/ai/chat` | `{"question", "context": {...}}` | AI Security Assistant |
| GET | `/ai/status` | — | LLM availability + model name |
| POST | `/threats/chain` | `{"events": [{event_type, risk_score, detail}]}` | Explicit correlation |

## Health

`GET /health` → honest component status:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "database": "connected",
  "nlp_model": "fallback (no fine-tuned model loaded)",
  "url_model": "fallback (no trained model)",
  "anomaly_model": "statistical_fallback",
  "llm": "available",
  "llm_model": "qwen2.5:1.5b"
}
```

## Errors

| Code | Meaning |
|---|---|
| 422 | Invalid input (blank text, bad URL, empty file) |
| 413 | Payload too large (> 8 MiB default) |
| 500 | Temporary server problem — client shows friendly retry message |
| 404 | Scan not found |

## Rate limiting (recommended production config)

The app ships with `slowapi` in requirements; enable per-IP limits in
`main.py` (e.g. 30/minute on `analyze/*`, 10/minute on `ai/*`) when exposing
beyond localhost.
