from __future__ import annotations

import json
from typing import Any, Dict

import httpx

from app.ai.prompts import build_prompt
from app.config import get_settings
from app.utils.logger import get_logger


logger = get_logger(__name__)


class LLMEngine:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def analyze(
        self,
        event_summary: str,
        evidence: str,
        history: str,
        retrieved_context: str,
        mitre: str,
    ) -> str:
        if not self.settings.llm_enabled:
            return self._fallback_analysis(event_summary, evidence, history, retrieved_context, mitre)
        prompt = build_prompt(event_summary, evidence, history, retrieved_context, mitre)
        payload: Dict[str, Any] = {
            "model": self.settings.ollama_model,
            "prompt": prompt,
            "stream": False,
        }
        try:
            timeout = httpx.Timeout(
                self.settings.ollama_timeout_seconds,
                connect=30.0,
                read=self.settings.ollama_timeout_seconds,
                write=60.0,
                pool=30.0,
            )
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(self.settings.ollama_url, json=payload)
                response.raise_for_status()
                data = response.json()
                return str(data.get("response", "")).strip() or self._fallback_analysis(
                    event_summary, evidence, history, retrieved_context, mitre
                )
        except Exception as exc:
            logger.warning("LLM request failed, using fallback narrative: %s", exc)
            return self._fallback_analysis(event_summary, evidence, history, retrieved_context, mitre)

    @staticmethod
    def _fallback_analysis(
        event_summary: str,
        evidence: str,
        history: str,
        retrieved_context: str,
        mitre: str,
    ) -> str:
        return (
            "AegisAI fallback analysis:\n"
            f"Summary: {event_summary}\n"
            f"Evidence:\n{evidence}\n"
            f"Historical context:\n{history or '- none'}\n"
            f"Threat intelligence:\n{retrieved_context or '- none'}\n"
            f"MITRE:\n{mitre or '- none'}\n"
            "Recommendations:\n- Validate source IPs\n- Review account activity\n- Contain suspicious sessions"
        )
