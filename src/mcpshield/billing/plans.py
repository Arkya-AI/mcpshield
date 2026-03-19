from __future__ import annotations

import os

PLANS: dict[str, dict] = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "scan_limit": 3,
        "stripe_price_id": None,
    },
    "starter": {
        "name": "Starter",
        "price_monthly": 49,
        "scan_limit": 50,
        "stripe_price_id": os.environ.get("STRIPE_PRICE_STARTER"),
    },
    "team": {
        "name": "Team",
        "price_monthly": 199,
        "scan_limit": 200,
        "stripe_price_id": os.environ.get("STRIPE_PRICE_TEAM"),
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": 2500,
        "scan_limit": 99999,
        "stripe_price_id": os.environ.get("STRIPE_PRICE_ENTERPRISE"),
    },
}


def get_plan(plan_name: str) -> dict:
    """Return plan dict for a given plan name, or raise KeyError if not found."""
    return PLANS[plan_name]


def get_plan_by_price_id(price_id: str) -> tuple[str, dict] | None:
    """Return (plan_name, plan_dict) for a given Stripe price ID, or None if not found."""
    for name, plan in PLANS.items():
        if plan["stripe_price_id"] == price_id:
            return name, plan
    return None
