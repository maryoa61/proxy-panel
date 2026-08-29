"""Database configuration for the Xray panel.

The project deliberately keeps the persistence layer small and portable: SQLite is
used by default, while ``DATABASE_URL`` can be supplied for tests or a future
external database.  Sessions are created per request by FastAPI's dependency.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _database_url() -> str:
    configured = os.getenv("DATABASE_URL") or os.getenv("DB_URL")
    if configured:
        return configured
    # Keep the default database out of the source tree when the application is
    # installed by the systemd installer, but preserve the historical path for
    # local development and backwards compatibility.
    return f"sqlite:///{PROJECT_ROOT / 'panel.db'}"


DATABASE_URL = _database_url()

if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine_kwargs = {"connect_args": connect_args, "pool_pre_ping": True}
    if DATABASE_URL.endswith(":memory:"):
        # Starlette's TestClient may create request sessions on another
        # thread; a StaticPool keeps an in-memory test database visible to all
        # of them.
        engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(DATABASE_URL, **engine_kwargs)
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)


# SQLite does not enforce foreign keys unless explicitly enabled.  Enabling it
# makes the cascade relationships used by clients and traffic logs reliable.
if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)

Base = declarative_base()


def get_db() -> Generator:
    """Yield a request-scoped SQLAlchemy session and always close it."""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
