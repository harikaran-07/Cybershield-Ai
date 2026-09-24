"""Risk Engine — combines all detection signals into one calibrated score.

Transparent by design: every input and weight is exposed so users can see WHY a
score was produced. Weights are configurable via environment variables.

This is an application-specific calibration, NOT a universal security standard.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import settings
from app.models.schemas import severity_for_score


@dataclass
class RiskInputs:
    """All possible signals. Unset signals contribute nothing."""
    nlp_probability: float | None = None        # 0–1 (RoBERTa / fallback)
    url_probability: float | None = None        # 0–1 (XGBoost / fallback)
    rule_score: int | None = None               # 0–100 (rule engine)
    file_risk: int | None = None                # 0–100 (static file analysis)
    app_risk: int | None = None                 # 0–100 (app permissions)
    network_anomaly: float | None = None        # 0–1 (isolation forest score)
    correlation_score: int | None = None        # 0–100 (threat correlation)
    indicator_count: int = 0                    # number of human-readable indicators


@dataclass
class RiskOutput:
    risk_score: int
    severity: str
    contributions: dict = field(default_factory=dict)
    weights_used: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "severity": self.severity,
            "contributions": self.contributions,
            "weights": self.weights_used,
        }


def _weights() -> dict[str, float]:
    raw = {
        "nlp": settings.WEIGHT_NLP,
        "url": settings.WEIGHT_URL,
        "rules": settings.WEIGHT_RULES,
        "file": settings.WEIGHT_FILE,
        "app": settings.WEIGHT_APP,
        "network": settings.WEIGHT_NETWORK,
        "correlation": settings.WEIGHT_CORRELATION,
    }
    total = sum(raw.values()) or 1.0
    return {k: round(v / total, 4) for k, v in raw.items()}


def compute_risk(inputs: RiskInputs) -> RiskOutput:
    """Weighted combination of available signals; missing signals are excluded
    and remaining weights are re-normalized so partial analyses stay fair."""
    w = _weights()
    values: dict[str, float] = {}
    if inputs.nlp_probability is not None:
        values["nlp"] = float(inputs.nlp_probability) * 100
    if inputs.url_probability is not None:
        values["url"] = float(inputs.url_probability) * 100
    if inputs.rule_score is not None:
        values["rules"] = float(inputs.rule_score)
    if inputs.file_risk is not None:
        values["file"] = float(inputs.file_risk)
    if inputs.app_risk is not None:
        values["app"] = float(inputs.app_risk)
    if inputs.network_anomaly is not None:
        values["network"] = float(inputs.network_anomaly) * 100
    if inputs.correlation_score is not None:
        values["correlation"] = float(inputs.correlation_score)

    if not values:
        # Nothing to score on — safe default with no fabricated confidence.
        return RiskOutput(0, "SAFE", {"note": "No detection signals available"},
                          {"note": "No signals"})

    # Re-normalize over the signals actually present
    active_w = {k: w[k] for k in values if k in w}
    wsum = sum(active_w.values()) or 1.0
    score = 0.0
    contributions: dict = {}
    for k, v in values.items():
        kw = active_w.get(k, 0.0) / wsum
        score += kw * v
        contributions[k] = {
            "value": round(v, 1),
            "weight_used": round(kw, 3),
            "points": round(kw * v, 1),
        }

    # Small boost when multiple independent signals agree (corroboration)
    if len(values) >= 3:
        high = sum(1 for v in values.values() if v >= 60)
        if high >= 2:
            boost = min(10, high * 3)
            score += boost
            contributions["corroboration_boost"] = {"value": high, "points": boost}

    # Indicator-count nudge (evidence breadth, capped)
    if inputs.indicator_count >= 4:
        score += 3

    risk = int(round(min(100.0, max(0.0, score))))
    return RiskOutput(risk, severity_for_score(risk), contributions, active_w)


def explain_risk(output: RiskOutput) -> str:
    """Human-readable 'why this score' summary.

    Defensive against non-dict entries (e.g. the "note" marker emitted when
    no detection signals were available at all).
    """
    parts = []
    for k, c in output.contributions.items():
        if not isinstance(c, dict):
            parts.append(str(c))
        elif k == "corroboration_boost":
            parts.append(f"{c['value']} independent high-risk signals agreed (+{c['points']})")
        else:
            parts.append(f"{k.title()}: {c['value']} (weight {c['weight_used']:.0%} → +{c['points']} pts)")
    return "; ".join(parts) if parts else "No signals contributed"
