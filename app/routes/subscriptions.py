"""
Subscription routes:
  GET  /subscriptions/tiers          — list all available tiers and features
  GET  /subscriptions/me             — current user's active subscription
    GET  /subscriptions/billing-history — billing history and renewal details
  POST /subscriptions/upgrade        — upgrade/switch tier
  POST /subscriptions/cancel         — cancel and revert to free
"""
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from ..extensions import db
from ..models.subscription import Subscription, TIERS
from ..models.audit import AuditLog

subscriptions_bp = Blueprint("subscriptions", __name__, url_prefix="/subscriptions")


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _verify_payment(provider, payment_reference, tier, billing_period):
    """Verify a provider-owned payment before changing the user's tier."""
    amount = TIERS[tier][f"{billing_period}_price_usd"]
    if current_app.config.get("BILLING_TEST_MODE") and payment_reference.startswith("test_"):
        return {"payment_method": f"{provider} test payment", "payment_status": "paid"}

    if provider == "stripe" and current_app.config.get("STRIPE_SECRET_KEY"):
        request_object = Request(
            f"https://api.stripe.com/v1/payment_intents/{payment_reference}",
            headers={"Authorization": f"Bearer {current_app.config['STRIPE_SECRET_KEY']}"},
        )
        try:
            with urlopen(request_object, timeout=10) as response:
                payment = json.load(response)
        except (HTTPError, URLError, ValueError):
            return None
        metadata = payment.get("metadata") or {}
        if (
            payment.get("status") == "succeeded"
            and int(payment.get("amount_received", 0)) == round(amount * 100)
            and str(payment.get("currency", "")).lower() == "usd"
            and metadata.get("tier") == tier
            and metadata.get("billing_period") == billing_period
        ):
            return {"payment_method": "Stripe", "payment_status": "paid"}
        return None

    # Paynow credentials are surfaced by the Integrations page. Its
    # transaction status endpoint requires the merchant's hash protocol and
    # should be implemented with the official Paynow SDK before enabling it.
    return None


@subscriptions_bp.get("/tiers")
def list_tiers():
    """Public — no login required. Show what each tier offers."""
    return jsonify(TIERS), 200


@subscriptions_bp.get("/me")
@login_required
def my_subscription():
    active_sub = (
        Subscription.query
        .filter_by(user_id=current_user.id, active=True)
        .order_by(Subscription.started_at.desc())
        .first()
    )
    if not active_sub:
        return jsonify({"tier": "free", "subscription": None}), 200

    return jsonify(
        {
            "tier":       active_sub.tier,
            "expires_at": active_sub.expires_at.isoformat() if active_sub.expires_at else None,
            "tier_info":  active_sub.tier_info(),
            "is_active":  active_sub.is_active(),
            "billing_period": active_sub.billing_period,
            "payment_method": active_sub.payment_method,
        }
    ), 200


@subscriptions_bp.get("/billing-history")
@login_required
def billing_history():
    active_sub = (
        Subscription.query
        .filter_by(user_id=current_user.id, active=True)
        .order_by(Subscription.started_at.desc())
        .first()
    )
    history = (
        Subscription.query
        .filter_by(user_id=current_user.id)
        .order_by(Subscription.started_at.desc())
        .all()
    )
    return jsonify({
        "current": active_sub.billing_dict() if active_sub else None,
        "next_renewal": active_sub.expires_at.isoformat() if active_sub and active_sub.expires_at else None,
        "payment_method": active_sub.payment_method if active_sub else None,
        "history": [subscription.billing_dict() for subscription in history],
    }), 200


@subscriptions_bp.post("/upgrade")
@login_required
def upgrade():
    data     = request.get_json(silent=True) or {}
    new_tier = data.get("tier", "").lower()
    billing_period = data.get("billing_period", "monthly").lower()
    provider = data.get("provider", current_app.config.get("BILLING_PROVIDER", "")).lower()
    payment_reference = str(data.get("payment_reference", "")).strip()

    if new_tier not in TIERS:
        return jsonify({"error": f"Unknown tier '{new_tier}'. Choose from: {list(TIERS)}."}), 400

    if new_tier == "free":
        return jsonify({"error": "Use /subscriptions/cancel to revert to free."}), 400

    if billing_period not in {"monthly", "annual"}:
        return jsonify({"error": "Billing period must be monthly or annual."}), 400

    if provider not in {"stripe", "paynow"} or not payment_reference:
        return jsonify({"error": "A configured payment provider and provider-issued payment reference are required."}), 400

    payment = _verify_payment(provider, payment_reference, new_tier, billing_period)
    if not payment:
        return jsonify({"error": "Payment could not be verified. The tier was not changed."}), 402

    # Deactivate any existing paid sub
    Subscription.query.filter_by(user_id=current_user.id, active=True).update({"active": False})
    db.session.commit()

    days = 365 if billing_period == "annual" else 30
    new_sub = Subscription.create_for_user(
        current_user, new_tier, days=days, billing_period=billing_period
    )
    new_sub.payment_method = payment["payment_method"]
    new_sub.payment_status = payment["payment_status"]
    db.session.add(new_sub)
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "SUBSCRIPTION_UPGRADE",
        extra={"new_tier": new_tier, "billing_period": billing_period, "billing_unit": "organization"}, ip_address=_ip(),
    )

    return jsonify(
        {
            "message":    f"Upgraded to {new_tier}.",
            "tier":       new_tier,
            "expires_at": new_sub.expires_at.isoformat() if new_sub.expires_at else None,
            "tier_info":  new_sub.tier_info(),
            "billing_period": billing_period,
            "billing_unit": "organization",
        }
    ), 200


@subscriptions_bp.post("/cancel")
@login_required
def cancel():
    Subscription.query.filter_by(user_id=current_user.id, active=True).update({"active": False})
    current_user.tier = "free"
    db.session.commit()

    AuditLog.write(db.session, current_user.id, "SUBSCRIPTION_CANCELLED", ip_address=_ip())
    return jsonify({"message": "Subscription cancelled. Back on free tier."}), 200
