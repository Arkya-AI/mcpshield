from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcpshield.auth.dependencies import get_db, require_auth
from mcpshield.billing.plans import PLANS, get_plan
from mcpshield.billing.stripe_client import (
    create_checkout_session,
    create_portal_session,
    get_or_create_customer,
    verify_webhook,
)
from mcpshield.db.models import User

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])

# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

PAID_PLANS = {"starter", "team", "enterprise"}


class CheckoutRequest(BaseModel):
    plan: str


class CheckoutResponse(BaseModel):
    checkout_url: str


class PortalResponse(BaseModel):
    portal_url: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_url(request: Request) -> str:
    """Derive the base URL from the incoming request (scheme + host)."""
    return str(request.base_url).rstrip("/")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    body: CheckoutRequest,
    request: Request,
    current_user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> CheckoutResponse:
    """Create a Stripe Checkout session for the requested paid plan."""
    if body.plan not in PAID_PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{body.plan}'. Must be one of: {', '.join(sorted(PAID_PLANS))}",
        )

    plan = get_plan(body.plan)
    price_id: str | None = plan.get("stripe_price_id")
    if not price_id:
        raise HTTPException(
            status_code=503,
            detail=f"Stripe price ID for plan '{body.plan}' is not configured.",
        )

    customer_id = get_or_create_customer(
        email=current_user.email,
        stripe_customer_id=current_user.stripe_customer_id,
    )

    # Persist the customer ID so future calls reuse it.
    if current_user.stripe_customer_id != customer_id:
        current_user.stripe_customer_id = customer_id
        db.add(current_user)
        await db.flush()

    base = _base_url(request)
    success_url = f"{base}/billing/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{base}/billing/cancel"

    checkout_url = create_checkout_session(
        customer_id=customer_id,
        price_id=price_id,
        success_url=success_url,
        cancel_url=cancel_url,
    )

    return CheckoutResponse(checkout_url=checkout_url)


@router.post("/webhook", status_code=200)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(..., alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Handle incoming Stripe webhook events."""
    payload = await request.body()
    event = verify_webhook(payload, stripe_signature)

    event_type: str = event.get("type", "")
    data_object: dict = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(db, data_object)

    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(db, data_object)

    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(db, data_object)

    return {"status": "ok"}


@router.get("/portal", response_model=PortalResponse)
async def billing_portal(
    request: Request,
    current_user: User = Depends(require_auth),
) -> PortalResponse:
    """Create a Stripe Billing Portal session for the current user."""
    if not current_user.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No Stripe customer found for this account. Please subscribe to a plan first.",
        )

    base = _base_url(request)
    return_url = f"{base}/dashboard"

    portal_url = create_portal_session(
        customer_id=current_user.stripe_customer_id,
        return_url=return_url,
    )

    return PortalResponse(portal_url=portal_url)


@router.get("/plans")
async def list_plans() -> dict:
    """Return available plans with pricing (public endpoint)."""
    public_plans = {}
    for plan_name, plan in PLANS.items():
        public_plans[plan_name] = {
            "name": plan["name"],
            "price_monthly": plan["price_monthly"],
            "scan_limit": plan["scan_limit"],
        }
    return {"plans": public_plans}


# ---------------------------------------------------------------------------
# Webhook event handlers
# ---------------------------------------------------------------------------

async def _handle_checkout_completed(db: AsyncSession, session: dict) -> None:
    """Update user record after a successful checkout."""
    customer_id: str | None = session.get("customer")
    subscription_id: str | None = session.get("subscription")

    if not customer_id:
        return

    result = await db.execute(select(User).where(User.stripe_customer_id == customer_id))
    user: User | None = result.scalar_one_or_none()
    if not user:
        return

    plan_name = _plan_from_subscription(subscription_id)

    if plan_name:
        user.plan = plan_name
    if subscription_id:
        user.stripe_subscription_id = subscription_id

    db.add(user)
    await db.flush()


async def _handle_subscription_updated(db: AsyncSession, subscription: dict) -> None:
    """Update user plan when a subscription changes."""
    customer_id: str | None = subscription.get("customer")
    subscription_id: str | None = subscription.get("id")

    if not customer_id:
        return

    result = await db.execute(select(User).where(User.stripe_customer_id == customer_id))
    user: User | None = result.scalar_one_or_none()
    if not user:
        return

    plan_name = _plan_from_subscription_object(subscription)
    if plan_name:
        user.plan = plan_name
    if subscription_id:
        user.stripe_subscription_id = subscription_id

    db.add(user)
    await db.flush()


async def _handle_subscription_deleted(db: AsyncSession, subscription: dict) -> None:
    """Downgrade user to free plan when their subscription is cancelled."""
    customer_id: str | None = subscription.get("customer")

    if not customer_id:
        return

    result = await db.execute(select(User).where(User.stripe_customer_id == customer_id))
    user: User | None = result.scalar_one_or_none()
    if not user:
        return

    user.plan = "free"
    user.stripe_subscription_id = None

    db.add(user)
    await db.flush()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _plan_from_subscription(subscription_id: str | None) -> str | None:
    """Fetch a Stripe subscription and return the matching plan name."""
    if not subscription_id:
        return None

    import stripe  # local import to avoid circular issues at module load

    try:
        sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price"])
        return _plan_from_subscription_object(dict(sub))
    except stripe.StripeError:
        return None


def _plan_from_subscription_object(subscription: dict) -> str | None:
    """Resolve plan name from a subscription dict (already fetched)."""
    from mcpshield.billing.plans import get_plan_by_price_id  # avoid top-level circular import

    items = subscription.get("items", {})
    data = items.get("data", []) if isinstance(items, dict) else []

    for item in data:
        price = item.get("price", {})
        price_id: str | None = price.get("id") if isinstance(price, dict) else None
        if price_id:
            result = get_plan_by_price_id(price_id)
            if result:
                plan_name, _ = result
                return plan_name

    return None
