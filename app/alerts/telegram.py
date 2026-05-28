from __future__ import annotations

import httpx

from app.config import get_settings
from app.utils.logger import get_logger


logger = get_logger(__name__)
MAX_TELEGRAM_MESSAGE_CHARS = 4000


class TelegramAlerter:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._skip_logged = False
        self.last_error: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.settings.telegram_bot_token and self.settings.telegram_chat_id)

    @property
    def ready(self) -> bool:
        return self.settings.telegram_enabled and self.configured

    def status_reason(self) -> str:
        if not self.settings.telegram_bot_token:
            return "telegram_missing_token"
        if not self.settings.telegram_chat_id:
            return "telegram_missing_chat_id"
        if not self.settings.telegram_enabled:
            return "telegram_disabled"
        return "ready"

    def _trim_message(self, message: str) -> str:
        if len(message) <= MAX_TELEGRAM_MESSAGE_CHARS:
            return message
        suffix = "\n...[trimmed]"
        return message[: MAX_TELEGRAM_MESSAGE_CHARS - len(suffix)] + suffix

    def _log_skip_once(self, reason: str) -> None:
        if self._skip_logged:
            return
        logger.warning("Telegram alert skipped: %s", reason)
        self._skip_logged = True

    async def send(self, message: str) -> bool:
        reason = self.status_reason()
        if reason != "ready":
            self.last_error = reason
            self._log_skip_once(reason)
            return False
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.settings.telegram_chat_id,
            "text": self._trim_message(message),
            "disable_web_page_preview": True,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
            self.last_error = None
            return True
        except httpx.HTTPStatusError as exc:
            try:
                description = exc.response.json().get("description", "unknown Telegram error")
            except ValueError:
                description = exc.response.text[:200] or "unknown Telegram error"
            self.last_error = f"telegram_http_{exc.response.status_code}: {description}"
            logger.warning("Telegram alert failed: HTTP %s: %s", exc.response.status_code, description)
            return False
        except httpx.RequestError:
            self.last_error = "telegram_request_failed"
            logger.warning("Telegram alert failed: request error")
            return False
