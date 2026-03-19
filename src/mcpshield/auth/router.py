from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcpshield.auth.dependencies import get_db, get_current_user, require_auth
from mcpshield.auth.service import (
    create_access_token,
    get_plan_scan_limit,
    hash_password,
    verify_password,
)
from mcpshield.db.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SignupRequest(BaseModel):
    email: str = Field(..., description="User email address.")
    password: str = Field(..., min_length=8, description="Password (min 8 characters).")

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address.")
        return v

    @field_validator("password")
    @classmethod
    def _validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v


class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address.")
    password: str = Field(..., description="User password.")

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class UserSummary(BaseModel):
    """Minimal user info embedded in auth responses."""
    id: str
    email: str
    plan: str


class AuthResponse(BaseModel):
    """Returned by signup and login endpoints."""
    token: str
    user: UserSummary


class MeResponse(BaseModel):
    """Returned by the /me endpoint."""
    id: str
    email: str
    plan: str
    scans_today: int
    scan_limit: int
    created_at: datetime


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _build_auth_response(user: User) -> AuthResponse:
    token = create_access_token(
        user_id=user.id,
        email=user.email,
        plan=user.plan,
    )
    return AuthResponse(
        token=token,
        user=UserSummary(id=user.id, email=user.email, plan=user.plan),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/signup",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account",
)
async def signup(
    body: SignupRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Register a new user account.

    Returns a signed JWT access token and basic user details on success.
    Raises **409** if the email address is already registered.
    """
    # Check for duplicate email
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        plan="free",
        scans_today=0,
        scans_today_reset=datetime.now(timezone.utc).date(),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    # Generate the UUID in Python so we can return it immediately
    from uuid import uuid4
    user.id = str(uuid4())

    db.add(user)
    await db.flush()   # write to DB within the transaction; commit happens on session exit

    return _build_auth_response(user)


@router.post(
    "/login",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in to an existing account",
)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Authenticate with email and password.

    Returns a signed JWT access token on success.
    Raises **401** for invalid credentials (deliberately vague to prevent
    user enumeration).
    """
    result = await db.execute(select(User).where(User.email == body.email))
    user: User | None = result.scalar_one_or_none()

    # Constant-time-ish path: verify even if user is None to prevent timing attacks
    _DUMMY_HASH = "$2b$12$invalidhashusedtopreventimenumeration"
    candidate_hash = user.password_hash if user is not None else _DUMMY_HASH

    if not verify_password(body.password, candidate_hash) or user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _build_auth_response(user)


@router.get(
    "/me",
    response_model=MeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
)
async def me(
    user: User = Depends(require_auth),
) -> MeResponse:
    """Return the authenticated user's profile including scan usage.

    Requires a valid ``Authorization: Bearer <token>`` header.
    Raises **401** if no valid token is provided.
    """
    return MeResponse(
        id=user.id,
        email=user.email,
        plan=user.plan,
        scans_today=user.scans_today,
        scan_limit=get_plan_scan_limit(user.plan),
        created_at=user.created_at,
    )
