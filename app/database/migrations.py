from __future__ import annotations

from app.database.db import init_db


def run_migrations() -> None:
    init_db()
