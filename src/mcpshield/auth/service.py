from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_JWT_ALGORITHM = "HS256"
_JWT_EXPIRY_HOURS = 24

# Daily scan limits per plan tier
_PLAN_LIMITS: dict[str, int] = {
    "free": 3,
    "starter": 50,
    "team": 200,
    "enterprise": 99999,
}

_DEFAULT_JWT_SECRET = "change-me-in-production"


def _jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET", _DEFAULT_JWT_SECRET)
    if secret == _DEFAULT_JWT_SECRET:
        import warnings
        warnings.warn(
            "JWT_SECRET is not set — using an insecure default. "
            "Set the JWT_SECRET environment variable in production.",
            stacklevel=2,
        )
    return secret


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*.

    bcrypt automatically embeds the salt and work factor in the returned
    string, making it self-contained for storage.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Return ``True`` if *password* matches *password_hash*."""
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, email: str, plan: str) -> str:
    """Create a signed JWT access token valid for 24 hours.

    The payload includes:
    - ``sub``: user ID
    - ``email``: user email
    - ``plan``: subscription plan
    - ``exp``: expiry timestamp (UTC)
    - ``iat``: issued-at timestamp (UTC)
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "plan": plan,
        "iat": now,
        "exp": now + timedelta(hours=_JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=_JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token.

    Raises ``jwt.PyJWTError`` (or a subclass) if the token is invalid,
    expired, or has a bad signature — callers must handle these.
    """
    return jwt.decode(
        token,
        _jwt_secret(),
        algorithms=[_JWT_ALGORITHM],
        options={"require": ["sub", "email", "plan", "exp", "iat"]},
    )


# ---------------------------------------------------------------------------
# Plan helpers
# ---------------------------------------------------------------------------

def get_plan_scan_limit(plan: str) -> int:
    """Return the daily scan limit for the given *plan* tier.

    Unknown plan strings fall back to the ``free`` tier limit so that any
    future plan misconfigurations degrade safely rather than allowing
    unlimited access.
    """
    return _PLAN_LIMITS.get(plan, _PLAN_LIMITS["free"])
