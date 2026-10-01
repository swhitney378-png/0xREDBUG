"""
Subscription routes:
  GET  /subscriptions/tiers          — list all available tiers and features
  GET  /subscriptions/me             — current user's active subscription
  POST /subscriptions/upgrade        — upgrade/switch tier
  POST /subscriptions/cancel         — cancel and revert to free
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from ..extensions import db
from ..models.subscription import Subscription, TIERS
from ..models.audit import AuditLog

subscriptions_bp = Blueprint("subscriptions", __name__, url_prefix="/subscriptions")


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


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

    return jsonify({
        "tier":         active_sub.tier,
        "expires_at":   active_sub.expires_at.isoformat() if active_sub.expires_at else None,
        "tier_info":    active_sub.tier_info(),
        "is_active":    active_sub.is_active(),
    }), 200


@subscriptions_bp.post("/upgrade")
@login_required
def upgrade():
    """
    In a real deployment this would integrate with Stripe or Paynow (Zimbabwe).
    For now it accepts a tier name + a simulated payment_token and upgrades directly.
    """
    data = request.get_json(silent=True) or {}
    new_tier = data.get("tier", "").lower()

    if new_tier not in TIERS:
        return jsonify({"error": f"Unknown tier '{new_tier}'. Choose from: {list(TIERS)}."}), 400

    if new_tier == "free":
        return jsonify({"error": "Use /subscriptions/cancel to revert to free."}), 400

    # Deactivate any existing paid sub
    Subscription.query.filter_by(user_id=current_user.id, active=True).update({"active": False})
    db.session.commit()

    # Days for tier
    days_by_tier = {"pro": 30, "enterprise": 30}
    new_sub = Subscription.create_for_user(current_user, new_tier, days=days_by_tier.get(new_tier, 30))
    db.session.add(new_sub)
    db.session.commit()

    AuditLog.write(db.session, current_user.id, "SUBSCRIPTION_UPGRADE",
                   extra={"new_tier": new_tier}, ip_address=_ip())

    return jsonify({
        "message":    f"Upgraded to {new_tier}.",
        "tier":       new_tier,
        "expires_at": new_sub.expires_at.isoformat() if new_sub.expires_at else None,
        "tier_info":  new_sub.tier_info(),
    }), 200


@subscriptions_bp.post("/cancel")
@login_required
def cancel():
    Subscription.query.filter_by(user_id=current_user.id, active=True).update({"active": False})
    current_user.tier = "free"
    db.session.commit()

    AuditLog.write(db.session, current_user.id, "SUBSCRIPTION_CANCELLED", ip_address=_ip())
    return jsonify({"message": "Subscription cancelled. Back on free tier."}), 200
