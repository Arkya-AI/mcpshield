from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeDecorator

from mcpshield.db.engine import Base


# ---------------------------------------------------------------------------
# Portable UUID column type
# ---------------------------------------------------------------------------
# PostgreSQL has a native UUID type; SQLite stores it as a VARCHAR(36).
# This decorator transparently handles both.

class UUIDString(TypeDecorator):
    """Store UUIDs as native PG UUID on Postgres, VARCHAR(36) elsewhere."""

    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=False))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return str(value)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid4())


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------

class User(Base):
    """Registered user account."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        UUIDString,
        primary_key=True,
        default=_new_uuid,
        server_default=None,
    )
    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    plan: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="free",
        server_default="free",
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        default=None,
    )
    stripe_subscription_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        default=None,
    )
    scans_today: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    scans_today_reset: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    # Relationship — one user has many scan records
    scan_records: Mapped[list[ScanRecord]] = relationship(
        "ScanRecord",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} email={self.email!r} plan={self.plan!r}>"


# ---------------------------------------------------------------------------
# ScanRecord model
# ---------------------------------------------------------------------------

class ScanRecord(Base):
    """Persisted result of a single scan run."""

    __tablename__ = "scan_records"

    id: Mapped[str] = mapped_column(
        UUIDString,
        primary_key=True,
        default=_new_uuid,
        server_default=None,
    )
    user_id: Mapped[str | None] = mapped_column(
        UUIDString,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    config_hash: Mapped[str] = mapped_column(
        String(64),   # SHA-256 hex digest
        nullable=False,
        index=True,
    )
    server_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    total_findings: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    worst_grade: Mapped[str] = mapped_column(
        String(1),
        nullable=False,
        default="A",
    )
    results_json: Mapped[Any] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    # Relationship back to the user (may be None for anonymous scans)
    user: Mapped[User | None] = relationship(
        "User",
        back_populates="scan_records",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanRecord id={self.id!r} user_id={self.user_id!r} "
            f"servers={self.server_count} findings={self.total_findings} "
            f"grade={self.worst_grade!r}>"
        )
