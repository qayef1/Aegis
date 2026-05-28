from __future__ import annotations

from app.schemas import CorrelatedThreat, SuspiciousEvent


def format_event_alert(event: SuspiciousEvent) -> str:
    evidence = "\n".join(f"- {item.get('line', '')}" for item in event.raw_evidence[:3]) or "- no evidence captured"
    mitre = ", ".join(event.mitre_techniques) or "N/A"
    return (
        f"[AegisAI] {event.severity.upper()} {event.title}\n"
        f"Summary: {event.summary}\n"
        f"Risk: {event.risk_score} | Confidence: {event.confidence}\n"
        f"MITRE: {mitre}\n"
        f"Evidence:\n{evidence}"
    )


def format_correlated_alert(threat: CorrelatedThreat) -> str:
    mitre = ", ".join(threat.mitre_techniques) or "N/A"
    recommendations = "\n".join(f"- {item}" for item in threat.recommendations)
    return (
        f"[AegisAI] {threat.severity.upper()} {threat.title}\n"
        f"Risk: {threat.risk_score} | Confidence: {threat.confidence}\n"
        f"MITRE: {mitre}\n"
        f"Narrative:\n{threat.narrative}\n"
        f"Recommendations:\n{recommendations}"
    )
