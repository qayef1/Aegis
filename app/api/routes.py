from __future__ import annotations

from fastapi import APIRouter

from app.database.db import get_db_session
from app.database.models import AttackHistoryRecord
from app.runtime import runtime


router = APIRouter()


def _serialize_record(record) -> dict:
    data = record.__dict__.copy()
    data.pop("_sa_instance_state", None)
    for key, value in list(data.items()):
        if hasattr(value, "isoformat"):
            data[key] = value.isoformat()
    return data


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "AegisAI"}


@router.get("/events")
async def events(limit: int = 100) -> list[dict]:
    return [_serialize_record(record) for record in runtime.fetch_events(limit)]


@router.get("/alerts")
async def alerts(limit: int = 100) -> list[dict]:
    return [_serialize_record(record) for record in runtime.fetch_alerts(limit)]


@router.post("/telegram/test")
async def telegram_test() -> dict:
    return await runtime.send_test_telegram()


@router.get("/stats")
async def stats() -> dict:
    return runtime.fetch_stats()


@router.get("/history")
async def history(limit: int = 50) -> list[dict]:
    with get_db_session() as session:
        records = session.query(AttackHistoryRecord).order_by(AttackHistoryRecord.created_at.desc()).limit(limit).all()
    return [_serialize_record(record) for record in records]


@router.get("/threats")
async def threats(limit: int = 100) -> list[dict]:
    return await alerts(limit)


@router.get("/attacks")
async def attacks(limit: int = 100) -> list[dict]:
    return await history(limit)


@router.get("/connections")
async def connections(limit: int = 100) -> list[dict]:
    events = runtime.fetch_events(limit)
    return [_serialize_record(record) for record in events if record.source == "connections"]
