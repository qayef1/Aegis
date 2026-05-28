from __future__ import annotations

from typing import Dict


SEVERITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 90,
}


def calculate_risk(severity: str, confidence: int, weight: int = 1) -> int:
    base = SEVERITY_SCORES.get(severity.lower(), 30)
    score = int((base * 0.6 + confidence * 0.4) * weight)
    return max(1, min(score, 100))


def score_bundle(severity: str, confidence: int, weight: int = 1) -> Dict[str, int | str]:
    return {
        "severity": severity,
        "confidence": confidence,
        "risk_score": calculate_risk(severity, confidence, weight),
    }
