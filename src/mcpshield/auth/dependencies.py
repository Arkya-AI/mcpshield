from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import date, datetime, timezone

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcpshield.auth.service import decode_access_token, get_plan_scan_limit
from mcpshield.db.engine import get_session
from mcpshield.db.models import User

# ---------------------------------------------------------------------------
# Database session dependency
# ---------------------------------------------------------------------------


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield an async database session per request."""
    async for session in get_session():
        yield session


# ---------------------------------------------------------------------------
# Authentication dependencies
# ---------------------------------------------------------------------------


async def get_current_user(
    authorization: str | None = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Extract the authenticated user from the ``Authorization`` header.

    Expects the header value to be ``Bearer <token>``.  Returns ``None``
    if the header is missing, malformed, or the token is invalid/expired.
    The user row is fetched from the database to ensure it still exists.
    """
    if not authorization:
        return None

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        return None

    user_id: str | None = payload.get("sub")
    if not user_id:
        return None

    result = await db.execute(select(User).where(User.id == user_id))
    user: User | None = result.scalar_one_or_none()
    return user


async def require_auth(
    user: User | None = Depends(get_current_user),
) -> User:
    """FastAPI dependency: raise HTTP 401 if the request is not authenticated.

    Use as ``Depends(require_auth)`` on routes that must have a logged-in user.
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ---------------------------------------------------------------------------
# Scan-limit dependency
# ---------------------------------------------------------------------------


async def check_scan_limit(
    user: User,
    db: AsyncSession,
) -> None:
    """Check whether *user* has remaining scans for today.

    - Resets ``scans_today`` to 0 when the calendar date has advanced.
    - Raises HTTP 429 if the daily limit is exhausted.
    - Does **not** increment the counter — callers should do that after a
      successful scan to avoid counting failed attempts.

    This is a plain async function (not a FastAPI dependency) so it can be
    called from route handlers that already have access to the user and db
    objects.
    """
    today = datetime.now(timezone.utc).date()

    # Reset counter if the reset date is in the past (or not yet set)
    if user.scans_today_reset is None or user.scans_today_reset < today:
        user.scans_today = 0
        user.scans_today_reset = today
        db.add(user)
        await db.flush()

    limit = get_plan_scan_limit(user.plan)
    if user.scans_today >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Daily scan limit reached ({limit} scans/day on the "
                f"'{user.plan}' plan). Upgrade your plan for more scans."
            ),
            headers={"Retry-After": _seconds_until_midnight()},
        )


def _seconds_until_midnight() -> str:
    """Return the number of seconds until the next UTC midnight as a string."""
    now = datetime.now(timezone.utc)
    midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    from datetime import timedelta
    midnight += timedelta(days=1)
    return str(int((midnight - now).total_seconds()))
