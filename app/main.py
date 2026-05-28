from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.config import get_settings
from app.database.db import init_db
from app.runtime import runtime
from app.utils.logger import configure_logging


settings = get_settings()
configure_logging(settings.log_level)
init_db()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await runtime.startup()
    yield
    await runtime.shutdown()


app = FastAPI(title="AegisAI", version="1.0.0", lifespan=lifespan)
app.include_router(router)
