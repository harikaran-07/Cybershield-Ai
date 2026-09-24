"""Network Security service — privacy-preserving metadata anomaly detection.

Only destination hostnames/counts/sizes are analyzed — never packet contents,
passwords, or message bodies. Uses Isolation Forest when a trained model exists
(app/ml/anomaly_model/model.pkl), else a transparent statistical fallback.
"""
from __future__ import annotations

import logging
import math
from collections import Counter
from functools import lru_cache

from app.core.config import ANOMALY_MODEL_DIR, settings

logger = logging.getLogger(__name__)

_KNOWN_GOOD_HOSTS = {
    "google.com", "android.googleapis.com", "googleapis.com", "gstatic.com",
    "android.clients.google.com", "play.googleapis.com", "apple.com",
    "cloudflare.com", "amazonaws.com", "microsoft.com", "1.1.1.1", "8.8.8.8",
}
_SUSPICIOUS_HOST_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "buzz", "cfd"}
_RAW_IP_HOST = {"host_is_raw_ip"}


@lru_cache
def _get_anomaly_model():
    import os
    path = ANOMALY_MODEL_DIR  # CWD-independent (see app.core.config.resolve_model_path)
    model_file = os.path.join(path, "model.pkl")
    if not os.path.exists(model_file):
        return None
    try:
        import joblib
        model = joblib.load(model_file)
        logger.info("Loaded Isolation Forest from %s", model_file)
        return model
    except Exception as exc:  # pragma: no cover
        logger.warning("Anomaly model load failed (%s); using statistical fallback", exc)
        return None


def anomaly_model_status() -> str:
    return "isolation_forest" if _get_anomaly_model() else "statistical_fallback"


def _featurize(stats: list[dict]) -> list[list[float]]:
    """Privacy-safe features: per-destination counts/sizes/entropy — no payloads."""
    total_conns = sum(s.get("connection_count", 0) for s in stats) or 1
    total_bytes = sum(s.get("bytes_sent", 0) + s.get("bytes_received", 0) for s in stats) or 1
    feats = []
    for s in stats:
        conns = s.get("connection_count", 0)
        bs = s.get("bytes_sent", 0)
        br = s.get("bytes_received", 0)
        host = str(s.get("destination", "")).lower()
        feats.append([
            conns,                                            # connection count
            math.log1p(bs + br),                              # log volume
            bs / (bs + br) if (bs + br) else 0.5,             # send/receive balance
            conns / total_conns,                              # destination share
            1.0 if re_ip(host) else 0.0,                      # raw IP destination
            1.0 if tld_sus(host) else 0.0,                    # suspicious TLD
            float(s.get("distinct_ports", 1)),                # port diversity
        ])
    return feats


def re_ip(host: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))


def tld_sus(host: str) -> bool:
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    return tld in _SUSPICIOUS_HOST_TLDS


def analyze_network(stats: list[dict], window_minutes: int = 15) -> dict:
    """Verdict: NORMAL | SUSPICIOUS | ANOMALOUS with human-readable notes."""
    if not stats:
        return {"verdict": "NORMAL", "anomaly_score": 0.0,
                "flagged_destinations": [], "notes": ["No network activity in window"]}

    model = _get_anomaly_model()
    flagged: list[str] = []
    notes: list[str] = []

    if model is not None:
        import numpy as np
        X = np.array(_featurize(stats))
        preds = model.predict(X)          # 1 = inlier, -1 = outlier
        scores = model.decision_function(X)  # higher = more normal
        # Normalize to 0..1 anomaly score
        anom = [(1 - float(s)) / 2 for s in scores]
        anomaly_score = float(max(anom))
        for s, p, a in zip(stats, preds, anom):
            if p == -1:
                flagged.append(str(s.get("destination")))
    else:
        # Transparent statistical fallback
        conns = [s.get("connection_count", 0) for s in stats]
        dests = [str(s.get("destination", "")).lower() for s in stats]
        counter = Counter(dests)
        total = sum(conns) or 1
        max_share = max((counter[d] for d in dests), default=0) / len(dests) if dests else 0
        # Heuristic 1: one destination dominating connection volume
        top_dest, top_count = counter.most_common(1)[0] if counter else ("", 0)
        share = top_count / max(1, sum(conns))
        if share > 0.6 and sum(conns) >= 20:
            flagged.append(top_dest)
            notes.append(f"{top_dest} received {share:.0%} of connections in the window")
        # Heuristic 2: raw-IP destinations (no DNS name)
        raw_ips = [d for d in dests if re_ip(d)]
        for ip in set(raw_ips):
            if ip not in _KNOWN_GOOD_HOSTS:
                flagged.append(ip)
                notes.append(f"Connections to raw IP {ip} without a domain name")
        # Heuristic 3: suspicious TLDs
        for d in set(dests):
            if tld_sus(d):
                flagged.append(d)
                notes.append(f"{d} uses a TLD commonly abused in campaigns")
        # Heuristic 4: unusually high total volume for the window
        total_conns = sum(conns)
        per_min = total_conns / max(1, window_minutes)
        if per_min > 50:
            notes.append(f"High connection volume: {total_conns} in {window_minutes} min")
        anomaly_score = min(1.0, (len(flagged) * 0.2 + (share if share > 0.6 else 0) +
                                  (0.2 if per_min > 50 else 0)))
        anomaly_score = round(anomaly_score, 3)

    flagged = sorted(set(flagged))
    verdict = "ANOMALOUS" if anomaly_score >= 0.65 or len(flagged) >= 3 else \
              "SUSPICIOUS" if anomaly_score >= 0.35 or flagged else "NORMAL"

    return {
        "verdict": verdict,
        "anomaly_score": round(anomaly_score, 3),
        "flagged_destinations": flagged,
        "notes": notes or ["Traffic pattern within expected ranges"],
        "model": anomaly_model_status(),
        "disclaimer": ("Metadata-only analysis. Message contents, passwords, and "
                       "authentication data are never inspected or stored."),
    }
