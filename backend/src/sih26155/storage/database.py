"""
PostgreSQL database engine and session factory.

Connection is configured via environment variable DATABASE_URL.
Falls back to a SQLite file database for local development if DATABASE_URL
is not set, so the application starts without any external services.

Set in .env (or environment):
    DATABASE_URL=postgresql+psycopg2://user:password@host:5432/dbname
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ---------------------------------------------------------------------------
# Connection URL
# ---------------------------------------------------------------------------

_DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "sqlite:///./data/compliance.db",   # local dev fallback
)

# SQLite needs check_same_thread=False for FastAPI
_connect_args: dict = (
    {"check_same_thread": False}
    if _DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    _DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,     # detect stale connections
    echo=False,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_all_tables() -> None:
    """Create all ORM-mapped tables if they do not already exist."""
    # Import models so they are registered on Base before create_all()
    from sih26155.storage import repositories  # noqa: F401
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Context-manager that yields a DB session and handles commit/rollback."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a session per request."""
    with get_db() as db:
        yield db
