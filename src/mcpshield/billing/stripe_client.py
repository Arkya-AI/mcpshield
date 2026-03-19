from __future__ import annotations

import os

import stripe
from fastapi import HTTPException

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")


def get_or_create_customer(email: str, stripe_customer_id: str | None) -> str:
    """Return existing Stripe customer ID or create a new customer and return the new ID."""
    if stripe_customer_id:
        try:
            customer = stripe.Customer.retrieve(stripe_customer_id)
            if getattr(customer, "deleted", False):
                raise ValueError("Customer has been deleted")
            return customer.id
        except stripe.StripeError as exc:
            raise HTTPException(status_code=502, detail=f"Stripe error retrieving customer: {exc}") from exc

    try:
        customer = stripe.Customer.create(email=email)
        return customer.id
    except stripe.StripeError as exc:
        raise HTTPException(status_code=502, detail=f"Stripe error creating customer: {exc}") from exc


def create_checkout_session(
    customer_id: str,
    price_id: str,
    success_url: str,
    cancel_url: str,
) -> str:
    """Create a Stripe Checkout session and return the session URL."""
    try:
        session = stripe.checkout.Session.create(
            customer=customer_id,
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return session.url
    except stripe.StripeError as exc:
        raise HTTPException(status_code=502, detail=f"Stripe error creating checkout session: {exc}") from exc


def create_portal_session(customer_id: str, return_url: str) -> str:
    """Create a Stripe Billing Portal session and return the portal URL."""
    try:
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return session.url
    except stripe.StripeError as exc:
        raise HTTPException(status_code=502, detail=f"Stripe error creating portal session: {exc}") from exc


def verify_webhook(payload: bytes, sig_header: str) -> dict:
    """Verify Stripe webhook signature and return the parsed event as a dict."""
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        return dict(event)
    except stripe.errors.SignatureVerificationError as exc:
        raise HTTPException(status_code=400, detail=f"Webhook signature verification failed: {exc}") from exc
    except stripe.StripeError as exc:
        raise HTTPException(status_code=400, detail=f"Stripe webhook error: {exc}") from exc
