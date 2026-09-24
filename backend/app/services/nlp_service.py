"""NLP service — text classification (DETECTION layer).

Model tiers, in priority order (the app reports EXACTLY which tier is live):
  1. "roberta"  — fine-tuned transformer in app/ml/roberta (if artifacts exist)
  2. "trained"  — TF-IDF + LogisticRegression in app/ml/nlp_prod
                  (scripts/train_prod_nlp.py; ships real evaluation metrics)
  3. "fallback" — transparent keyword heuristic, used only when no model loads

IMPORTANT — model status honesty:
- /health reports the LIVE tier. Nothing is ever faked as loaded.

Labels: SAFE | SPAM | SCAM | PHISHING
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache

from app.core.config import MODEL_DIR, NLP_PROD_MODEL_DIR
from app.services.rule_engine import analyze_message_rules

logger = logging.getLogger(__name__)

LABELS = ["SAFE", "SPAM", "SCAM", "PHISHING"]
FALLBACK_NOTE = (
    "Development fallback (keyword heuristic) — no trained model loaded. "
    "Place a trained model at MODEL_PATH or run scripts/train_prod_nlp.py."
)

# Keyword groups for the transparent fallback heuristic
_SCAM_PATTERNS: list[tuple[str, float]] = [
    (r"\b(your|the) account (is|will be|has been) (suspended|locked|blocked|disabled)\b", 0.30),
    (r"\bverify (your|the|immediately|now)\b", 0.22),
    (r"\b(account|card|subscription) (is|will be|has been) (suspended|locked|blocked)\b", 0.32),
    (r"\b(confirm|update) your (password|billing|payment|card)\b", 0.28),
    (r"\b(one[- ]time (code|password)|otp|cvv|pin)\b", 0.22),
    (r"\b(urgent|immediately|final notice|last warning|within 24 hours)\b", 0.20),
    (r"\b(click|tap|press) (the )?link\b", 0.15),
    (r"\b(you have won|congratulations|claim your prize|lucky winner)\b", 0.28),
    (r"\b(seed phrase|recovery phrase|private key)\b", 0.35),
    (r"\b(gift card|bitcoin|crypto (recovery|investment))\b", 0.25),
    (r"\b(delivery fee|customs fee|parcel held|reschedule delivery)\b", 0.20),
    (r"\b(irs|tax office|police department)\b.*\b(pay|fine|warrant)\b", 0.30),
]
_PHISHING_URL_HINT = re.compile(r"https?://|www\.|\b[a-z0-9-]+\.(com|net|org|xyz|top|link|click)\b", re.I)
_WORD_RE = re.compile(r"[a-z']+")


@lru_cache
def _get_trained_pipeline():
    """Load the trained TF-IDF+LogReg tier when artifacts exist; else None."""
    import os
    model_path = os.path.join(NLP_PROD_MODEL_DIR, "model.joblib")
    if not os.path.exists(model_path):
        return None
    try:
        import joblib
        pipe = joblib.load(model_path)
        labels = list(LABELS)
        lp = os.path.join(NLP_PROD_MODEL_DIR, "labels.json")
        if os.path.exists(lp):
            with open(lp) as f:
                labels = json.load(f).get("labels", labels)
        logger.info("Loaded trained text classifier from %s", model_path)
        return {"pipe": pipe, "labels": labels, "type": "trained_sklearn"}
    except Exception as exc:  # pragma: no cover — environment-specific
        logger.warning("Trained classifier load failed (%s); tiers degrade gracefully", exc)
        return None


@lru_cache
def _get_pipeline():
    """Load fine-tuned RoBERTa when artifacts exist; else None (fallback used)."""
    import os
    model_dir = MODEL_DIR  # CWD-independent, resolved in app.core.config
    if not os.path.isdir(model_dir):
        return None
    required = ("config.json", "tokenizer_config.json")
    if not all(os.path.exists(os.path.join(model_dir, r)) for r in required):
        logger.info("MODEL_PATH lacks tokenizer/config artifacts; using lower NLP tier")
        return None
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        device = "cuda" if torch.cuda.is_available() else "cpu"
        tok = AutoTokenizer.from_pretrained(model_dir)
        model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        model.to(device)
        model.eval()
        logger.info("Loaded fine-tuned RoBERTa from %s on %s", model_dir, device)
        return {"tokenizer": tok, "model": model, "device": device, "type": "roberta"}
    except Exception as exc:  # pragma: no cover — environment-specific
        logger.warning("RoBERTa load failed (%s); using lower NLP tier", exc)
        return None


def nlp_model_status() -> str:
    """Report exactly which tier is live — roberta > trained > fallback."""
    if _get_pipeline() is not None:
        return "roberta"
    if _get_trained_pipeline() is not None:
        return "trained (tf-idf + logistic regression)"
    return "fallback (no model loaded)"


def _fallback_classify(text: str) -> tuple[str, float, list[str]]:
    """Transparent keyword heuristic. Conservative — biased toward under-calling."""
    low = text.lower()
    score = 0.0
    matched: list[str] = []
    for pattern, weight in _SCAM_PATTERNS:
        if re.search(pattern, low):
            score += weight
            matched.append(pattern.split("\\b")[1] if "\\b" in pattern else pattern)
    has_url = bool(_PHISHING_URL_HINT.search(low))
    if has_url:
        score += 0.08
    score = min(0.97, score)
    if score >= 0.60:
        label = "SCAM"
    elif score >= 0.35:
        label = "SPAM"
    elif score >= 0.18:
        label = "PHISHING" if has_url else "SPAM"
    else:
        label = "SAFE"
    return label, round(score, 3), matched[:6]


def classify_text(text: str) -> dict:
    """Classify message/email text. Returns label, probability, method, indicators."""
    text = (text or "").strip()
    if not text:
        return {"label": "SAFE", "probability": 0.0, "method": "none", "indicators": []}

    # --- Tier 1: fine-tuned RoBERTa ---
    pipe = _get_pipeline()
    if pipe is not None:
        import torch
        tok, model, device = pipe["tokenizer"], pipe["model"], pipe["device"]
        inputs = tok(text[:2000], truncation=True, max_length=256, return_tensors="pt").to(device)
        with torch.no_grad():
            logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)[0].tolist()
        best_idx = int(max(range(len(probs)), key=lambda i: probs[i]))
        # Map model output index -> canonical label via the model's own config, else default order.
        # id2label values are stored as strings in config.json, so normalize before matching.
        id2label = getattr(model.config, "id2label", None) or {i: lbl for i, lbl in enumerate(LABELS)}
        raw_label = str(id2label.get(best_idx, LABELS[best_idx])).upper()
        label = raw_label if raw_label in LABELS else LABELS[best_idx]
        prob = round(float(probs[best_idx]), 3)
        indicators = [f"NLP model classified text as {label} (confidence {prob:.0%})"]
        return {"label": label, "probability": prob, "method": "roberta", "indicators": indicators}

    # --- Tier 2: trained TF-IDF + LogisticRegression classifier ---
    trained = _get_trained_pipeline()
    if trained is not None:
        # CRITICAL: proba columns follow the estimator's classes_ order
        # (alphabetical), NOT labels.json order. Map through classes_.
        # SEMANTICS: downstream risk engine expects THREAT probability, so for
        # a 4-class model we report 1 − P(SAFE) — NOT the top-class confidence
        # (a confidently-SAFE text would otherwise read as a 70% threat).
        pipe = trained["pipe"]
        classes = [str(c).upper() for c in getattr(pipe, "classes_", [])] or list(LABELS)
        proba = pipe.predict_proba([text[:2000]])[0]
        best_idx = int(max(range(len(proba)), key=lambda i: proba[i]))
        raw_label = classes[best_idx] if best_idx < len(classes) else LABELS[best_idx]
        label = raw_label if raw_label in LABELS else LABELS[best_idx]
        prob = round(float(proba[best_idx]), 3)
        # Threat probability = 1 − P(SAFE), clamped to the model's honest range.
        if "SAFE" in classes:
            threat = 1.0 - float(proba[classes.index("SAFE")])
        else:
            threat = float(proba[best_idx]) if label != "SAFE" else 0.0
        threat = round(min(0.97, max(0.0, threat)), 3)
        indicators = [
            f"Trained text classifier: {label} (model confidence {prob:.0%}, "
            f"threat probability {threat:.0%})"
        ]
        return {"label": label, "probability": threat, "method": "trained_sklearn",
                "indicators": indicators}

    # --- Tier 3: transparent keyword fallback ---
    label, prob, matched = _fallback_classify(text)
    indicators = [f"Matched scam pattern: {m}" for m in matched]
    if not indicators:
        indicators = ["No strong scam indicators matched"]
    return {
        "label": label,
        "probability": prob,
        "method": "fallback_heuristic",
        "indicators": indicators,
    }


def analyze_message_nlp(text: str) -> dict:
    """Full NLP analysis: classification + rule support for evidence."""
    result = classify_text(text)
    rules = analyze_message_rules(text)
    return {
        "nlp": result,
        "rules": {
            "rule_score": rules.rule_score,
            "hits": [{"code": h.code, "description": h.description, "weight": h.weight} for h in rules.hits],
            "urls": rules.urls,
            "urgency_score": rules.urgency_score,
        },
    }
