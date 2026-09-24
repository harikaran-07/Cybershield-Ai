"""URL analysis service — XGBoost classification + rule evidence.

DETECTION layer. Safe static analysis only: the URL is never fetched or visited.
If app/ml/url_model contains a trained model.json (scripts/train_models.py --url),
real XGBoost inference is used; otherwise a transparent rule-derived score is used
and /health reports url_model = "fallback (no trained model)".
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict
from functools import lru_cache

from app.core.config import URL_MODEL_DIR
from app.models.schemas import severity_for_score
from app.services.rule_engine import FEATURE_NAMES, describe_features, extract_url_features

logger = logging.getLogger(__name__)

_shortener_hosts = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "ow.ly",
}


@lru_cache(maxsize=1)
def _get_url_model():
    """Load trained XGBoost model when present; else None (rule fallback)."""
    import os
    model_path = os.path.join(URL_MODEL_DIR, "model.json")  # CWD-independent
    if not os.path.exists(model_path):
        return None
    try:
        import xgboost as xgb
        booster = xgb.Booster()
        booster.load_model(model_path)
        logger.info("Loaded XGBoost URL model from %s", model_path)
        return booster
    except Exception as exc:  # pragma: no cover
        logger.warning("XGBoost URL model load failed (%s); using rule fallback", exc)
        return None


def url_model_status() -> str:
    return "xgboost" if _get_url_model() else "fallback (no trained model)"


def url_risk_rules(url: str) -> dict:
    """Static rule analysis of a URL. Never fetches."""
    feats = extract_url_features(url)
    hits = describe_features(feats)
    rule_score = min(100, sum(h.weight for h in hits) * 2) if hits else 0
    return {
        "features": asdict(feats),
        "hits": [{"code": h.code, "description": h.description, "weight": h.weight} for h in hits],
        "rule_score": rule_score,
    }


def analyze_url(url: str, device_id: str | None = None) -> dict:
    """Full URL analysis: features + rules + optional XGBoost. Detection only."""
    url = (url or "").strip()
    if not url:
        return {"label": "SAFE", "probability": 0.0, "risk_score": 0, "severity": "SAFE",
                "indicators": ["Empty URL"], "features": {}, "rule_hits": []}

    feats = extract_url_features(url)
    hits = describe_features(feats)
    indicators = [h.description for h in hits]

    # --- ML classification (XGBoost when available) ---
    booster = _get_url_model()
    if booster is not None:
        import numpy as np
        import xgboost as xgb
        dmatrix = xgb.DMatrix(np.array([feats.to_vector()]), feature_names=FEATURE_NAMES)
        prob_phish = float(booster.predict(dmatrix)[0])
        method = "XGBoost"
        probability = round(prob_phish, 3)
    else:
        # Transparent fallback: blend rule score with structural penalties.
        rule_raw = sum(h.weight for h in hits)
        structural = (feats.has_ip_host * 20 + feats.has_punycode * 15 +
                      feats.uses_at_sign * 15 + feats.is_shortener * 10 +
                      feats.suspicious_tld * 10 + min(20, feats.suspicious_keywords * 5))
        probability = round(min(0.97, (rule_raw * 2 + structural) / 130), 3)
        method = "Rule Engine (ML model not loaded)"

    rule_score = min(100, int(sum(h.weight for h in hits) * 2))
    risk_score = int(round(100 * (0.65 * probability + 0.35 * (rule_score / 100))))
    risk_score = min(100, max(0, risk_score))
    severity = severity_for_score(risk_score)

    label = "PHISHING" if probability >= 0.70 else "SUSPICIOUS" if probability >= 0.40 else "SAFE"
    if label == "SAFE" and severity in ("LOW", "MEDIUM") and hits:
        label = "SUSPICIOUS"

    host = url.split("//")[-1].split("/")[0].lower() if url else ""
    recommendation = _recommendation(label, hits)

    return {
        "label": label,
        "probability": probability,
        "risk_score": risk_score,
        "severity": severity,
        "indicators": indicators or ["No structural phishing indicators found"],
        "method": method,
        "features": asdict(feats),
        "rule_hits": [{"code": h.code, "description": h.description} for h in hits],
        "host": host,
        "url_hash": hashlib.sha256(url.encode()).hexdigest(),
        "recommendation": recommendation,
        "note": "HTTPS alone does not mean a site is safe; analysis is static only.",
    }


def _recommendation(label: str, hits) -> str:
    if label == "PHISHING":
        return ("Do not open this link. Do not enter passwords, codes, or card details. "
                "If it claims to be from an organization, verify via its official app or website.")
    if label == "SUSPICIOUS":
        return ("This link shows some phishing traits. Avoid entering personal information; "
                "prefer typing the organization's official address yourself.")
    return "No major phishing traits found. Stay cautious with links from unknown senders."
