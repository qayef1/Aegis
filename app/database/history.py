from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import desc, select

from app.database.models import AttackHistoryRecord


class AttackHistoryStore:
    def record(self, session, actor_key: str, attack_type: str, summary: str, indicators: Dict[str, Any]) -> None:
        session.add(
            AttackHistoryRecord(
                actor_key=actor_key,
                attack_type=attack_type,
                summary=summary,
                indicators=indicators,
            )
        )

    def recent_for_actor(self, session, actor_key: str, limit: int = 10) -> List[AttackHistoryRecord]:
        stmt = (
            select(AttackHistoryRecord)
            .where(AttackHistoryRecord.actor_key == actor_key)
            .order_by(desc(AttackHistoryRecord.created_at))
            .limit(limit)
        )
        return list(session.scalars(stmt))
