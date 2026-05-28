from __future__ import annotations

from typing import Iterable


MAX_PROMPT_CHARS = 4000
TRUNCATION_MARKER = "\n... [trimmed]\n"


SYSTEM_PROMPT = """You are AegisAI, a local SOC/XDR analyst running on a Linux host.
You only receive summarized suspicious events, historical context, raw evidence excerpts, MITRE mappings, and retrieved threat intelligence.
Produce concise professional SOC analysis with:
1. Attack narrative
2. Why it matters
3. Raw evidence bullets
4. MITRE ATT&CK
5. Recommendations
Do not fabricate evidence. If evidence is weak, say so."""


def _trim_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    if max_chars <= len(TRUNCATION_MARKER):
        return value[:max_chars]
    return value[: max_chars - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _build_prompt_from_sections(
    event_summary: str,
    evidence: str,
    history: str,
    retrieved_context: str,
    mitre: str,
) -> str:
    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"Suspicious Event Summary:\n{event_summary}\n\n"
        f"Raw Evidence:\n{evidence}\n\n"
        f"Historical Context:\n{history}\n\n"
        f"Retrieved Threat Intelligence:\n{retrieved_context}\n\n"
        f"MITRE References:\n{mitre}\n\n"
        "Return a concise attack narrative with severity and recommendations."
    )


def trim_prompt(
    event_summary: str,
    evidence: str,
    history: str,
    retrieved_context: str,
    mitre: str,
    max_chars: int = MAX_PROMPT_CHARS,
) -> str:
    prompt = _build_prompt_from_sections(event_summary, evidence, history, retrieved_context, mitre)
    if len(prompt) <= max_chars:
        return prompt

    trimmed_sections = {
        "event_summary": _trim_text(event_summary, 1200),
        "evidence": _trim_text(evidence, 1200),
        "history": _trim_text(history, 350),
        "retrieved_context": _trim_text(retrieved_context, 550),
        "mitre": _trim_text(mitre, 500),
    }
    prompt = _build_prompt_from_sections(**trimmed_sections)
    if len(prompt) <= max_chars:
        return prompt

    # Keep the highest-signal SOC inputs first, then shrink lower-priority context.
    shrink_order = [
        ("history", 100),
        ("retrieved_context", 250),
        ("mitre", 300),
        ("evidence", 900),
        ("event_summary", 900),
    ]
    for key, limit in shrink_order:
        trimmed_sections[key] = _trim_text(trimmed_sections[key], limit)
        prompt = _build_prompt_from_sections(**trimmed_sections)
        if len(prompt) <= max_chars:
            return prompt

    return prompt[:max_chars]


def build_prompt(event_summary: str, evidence: str, history: str, retrieved_context: str, mitre: str) -> str:
    return trim_prompt(
        event_summary=event_summary,
        evidence=evidence,
        history=history,
        retrieved_context=retrieved_context,
        mitre=mitre,
    )


def join_lines(values: Iterable[str]) -> str:
    return "\n".join(f"- {value}" for value in values if value)
