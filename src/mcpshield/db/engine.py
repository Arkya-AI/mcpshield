from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# ---------------------------------------------------------------------------
# Declarative base — shared by all ORM models in this package
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Module-level singletons (lazily initialised on first call)
# ---------------------------------------------------------------------------

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None

_DEFAULT_URL = "sqlite+aiosqlite:///./mcpshield.db"


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL", _DEFAULT_URL)
    # Railway provides postgresql:// but we need postgresql+asyncpg:// for async
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def get_engine() -> AsyncEngine:
    """Return (and lazily create) the shared async engine.

    Supports both PostgreSQL (asyncpg driver) and SQLite (aiosqlite driver)
    depending on the scheme in ``DATABASE_URL``.  PostgreSQL connections get
    a small connection-pool; SQLite uses the single-connection default.
    """
    global _engine
    if _engine is None:
        url = _get_database_url()

        connect_args: dict = {}
        if url.startswith("sqlite"):
            # SQLite requires check_same_thread=False for async use
            connect_args = {"check_same_thread": False}
            _engine = create_async_engine(
                url,
                connect_args=connect_args,
                echo=os.environ.get("DB_ECHO", "").lower() in {"1", "true", "yes"},
            )
        else:
            # PostgreSQL via asyncpg — use a sensible pool size
            _engine = create_async_engine(
                url,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                echo=os.environ.get("DB_ECHO", "").lower() in {"1", "true", "yes"},
            )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return (and lazily create) the shared session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async generator that yields a database session.

    Intended for use as a FastAPI dependency via ``Depends(get_session)``.
    The session is automatically closed (and rolled back on error) after the
    request completes.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables defined in the ORM models.

    Call this once at application startup (e.g. in a FastAPI ``lifespan``
    handler).  It is safe to call multiple times — SQLAlchemy's
    ``create_all`` is idempotent when tables already exist.
    """
    # Import models here to ensure they are registered on Base.metadata
    from mcpshield.db import models as _models  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
