from __future__ import annotations

import asyncio
from typing import List

from sqlalchemy import desc, func, select

from app.ai.correlation_engine import CorrelationEngine
from app.alerts.formatter import format_correlated_alert, format_event_alert
from app.alerts.telegram import TelegramAlerter
from app.collectors.auth_collector import AuthCollector
from app.collectors.connection_collector import ConnectionCollector
from app.collectors.file_integrity_collector import FileIntegrityCollector
from app.collectors.history_collector import HistoryCollector
from app.collectors.package_collector import PackageCollector
from app.collectors.packet_collector import PacketCollector
from app.collectors.process_collector import ProcessCollector
from app.collectors.webapp_collector import WebAppCollector
from app.config import get_settings
from app.database.db import get_db_session
from app.database.models import AlertRecord, EventRecord
from app.detectors.bruteforce_detector import BruteForceDetector
from app.detectors.ddos_detector import DDoSDetector
from app.detectors.exfiltration_detector import ExfiltrationDetector
from app.detectors.file_integrity_detector import FileIntegrityDetector
from app.detectors.history_detector import HistoryDetector
from app.detectors.login_anomaly_detector import LoginAnomalyDetector
from app.detectors.package_detector import PackageDetector
from app.detectors.privilege_detector import PrivilegeDetector
from app.detectors.process_detector import ProcessDetector
from app.detectors.scan_detector import ScanDetector
from app.detectors.webapp_detector import WebAppDetector
from app.schemas import SuspiciousEvent
from app.threat_intelligence.updater import ThreatIntelUpdater
from app.utils.logger import get_logger


logger = get_logger(__name__)


class AegisRuntime:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.collectors = [
            AuthCollector(),
            WebAppCollector(),
            PackageCollector(),
            HistoryCollector(),
            ProcessCollector(),
            ConnectionCollector(),
            PacketCollector(),
            FileIntegrityCollector(),
        ]
        self.detectors = [
            BruteForceDetector(),
            WebAppDetector(),
            ScanDetector(),
            DDoSDetector(),
            LoginAnomalyDetector(),
            PrivilegeDetector(),
            ExfiltrationDetector(),
            ProcessDetector(),
            PackageDetector(),
            HistoryDetector(),
            FileIntegrityDetector(),
        ]
        self.correlation = CorrelationEngine()
        self.telegram = TelegramAlerter()
        self.threat_updater = ThreatIntelUpdater()
        self._task: asyncio.Task | None = None

    async def startup(self) -> None:
        if self.settings.threat_sync_enabled:
            await self.threat_updater.sync()
        self._task = asyncio.create_task(self._loop())

    async def shutdown(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception as exc:
                logger.exception("Runtime loop failed: %s", exc)
            for detector in self.detectors:
                detector.tick()
            await asyncio.sleep(self.settings.scheduler_interval_seconds)

    async def run_once(self) -> None:
        all_events: List[SuspiciousEvent] = []
        for collector in self.collectors:
            observations = await collector.collect()
            for observation in observations:
                for detector in self.detectors:
                    all_events.extend(await detector.process(observation))
        if not all_events:
            return
        records: List[EventRecord] = []
        pending_alerts: list[tuple[int, int, str]] = []
        with get_db_session() as session:
            for event in all_events:
                record = EventRecord(
                    event_type=event.event_type,
                    source=event.source,
                    severity=event.severity,
                    confidence=event.confidence,
                    risk_score=event.risk_score,
                    title=event.title,
                    summary=event.summary,
                    raw_evidence=event.raw_evidence,
                    indicators=event.indicators,
                    mitre_techniques=event.mitre_techniques,
                    metadata_json=event.metadata,
                )
                session.add(record)
                session.flush()
                records.append(record)
                alert_body = format_event_alert(event)
                alert = AlertRecord(
                    event_id=record.id,
                    title=event.title,
                    severity=event.severity,
                    body=alert_body,
                    status="pending",
                )
                session.add(alert)
                session.flush()
                pending_alerts.append((alert.id, event.risk_score, alert_body))
        await self._deliver_alerts(pending_alerts)
        correlated_alert_body: str | None = None
        pending_correlated_alerts: list[tuple[int, int, str]] = []
        with get_db_session() as session:
            records = list(
                session.scalars(
                    select(EventRecord)
                    .where(EventRecord.id.in_([record.id for record in records]))
                    .order_by(EventRecord.id)
                )
            )
            correlated = await self.correlation.correlate(session, records)
            if correlated:
                correlated_alert_body = format_correlated_alert(correlated)
                alert = AlertRecord(
                    event_id=None,
                    title=correlated.title,
                    severity=correlated.severity,
                    body=correlated_alert_body,
                    status="pending",
                )
                session.add(alert)
                session.flush()
                pending_correlated_alerts.append((alert.id, correlated.risk_score, correlated_alert_body))
        if correlated_alert_body:
            await self._deliver_alerts(pending_correlated_alerts, force=True)

    async def _deliver_alerts(self, alerts: list[tuple[int, int, str]], force: bool = False) -> None:
        send_attempts = 0
        status_updates: list[tuple[int, str]] = []
        for alert_id, risk_score, body in alerts:
            if not force and risk_score < self.settings.telegram_min_risk_score:
                status = "skipped_low_risk"
            elif not force and send_attempts >= self.settings.telegram_max_alerts_per_tick:
                status = "skipped_rate_limited"
            else:
                reason = self.telegram.status_reason()
                if reason != "ready":
                    status = reason
                    await self.telegram.send(body)
                else:
                    send_attempts += 1
                    status = "sent" if await self.telegram.send(body) else "telegram_failed"
            status_updates.append((alert_id, status))
        with get_db_session() as session:
            for alert_id, status in status_updates:
                record = session.get(AlertRecord, alert_id)
                if record:
                    record.status = status

    async def send_test_telegram(self) -> dict:
        reason = self.telegram.status_reason()
        if reason != "ready":
            return {
                "configured": self.telegram.configured,
                "enabled": self.settings.telegram_enabled,
                "sent": False,
                "status": reason,
            }
        sent = await self.telegram.send("AegisAI Telegram test alert")
        return {
            "configured": self.telegram.configured,
            "enabled": self.settings.telegram_enabled,
            "sent": sent,
            "status": "sent" if sent else "telegram_failed",
            "error": self.telegram.last_error,
        }

    def fetch_events(self, limit: int = 100) -> List[EventRecord]:
        with get_db_session() as session:
            stmt = select(EventRecord).order_by(desc(EventRecord.created_at)).limit(limit)
            return list(session.scalars(stmt))

    def fetch_alerts(self, limit: int = 100) -> List[AlertRecord]:
        with get_db_session() as session:
            stmt = select(AlertRecord).order_by(desc(AlertRecord.created_at)).limit(limit)
            return list(session.scalars(stmt))

    def fetch_stats(self) -> dict:
        with get_db_session() as session:
            events_total = session.scalar(select(func.count()).select_from(EventRecord)) or 0
            alerts_total = session.scalar(select(func.count()).select_from(AlertRecord)) or 0
            critical_events = session.scalar(
                select(func.count()).select_from(EventRecord).where(EventRecord.severity == "critical")
            ) or 0
            return {
                "events_total": events_total,
                "alerts_total": alerts_total,
                "critical_events": critical_events,
            }


runtime = AegisRuntime()
