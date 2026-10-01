"""
Admin routes (admin role only):
  GET  /admin/users               — list all users
  POST /admin/users               — create a user
  PUT  /admin/users/<id>          — update role / tier / status
  GET  /admin/audit               — view audit log (paginated)
  GET  /admin/audit/verify-chain  — verify audit hash chain integrity
  GET  /admin/stats               — dashboard summary stats
"""
import json
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user, login_required
from ..extensions import db
from ..models.user import User, Role
from ..models.audit import AuditLog
from ..models.patient import MedicalRecord
from ..models.subscription import Subscription, TIERS
from .subscriptions import _verify_payment
from ..utils.decorators import admin_only

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ─── Users ────────────────────────────────────────────────────────────────────

@admin_bp.get("/users")
@login_required
@admin_only
def list_users():
    users = User.query.order_by(User.id).all()
    return jsonify(
        [
            {
                "id":          u.id,
                "username":    u.username,
                "email":       u.email,
                "role":        u.role,
                "department":  u.department,
                "tier":        u.tier,
                "is_active":   u.is_active,
                "mfa_enabled": u.mfa_enabled,
                "created_at":  u.created_at.isoformat(),
            }
            for u in users
        ]
    ), 200


@admin_bp.post("/users")
@login_required
@admin_only
def create_user():
    data     = request.get_json(silent=True) or {}
    required = ["username", "email", "password"]
    if not all(data.get(f) for f in required):
        return jsonify({"error": "username, email and password required."}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already taken."}), 409

    if data.get("role") not in Role.ALL:
        return jsonify({"error": f"role must be one of {Role.ALL}."}), 400

    requested_tier = data.get("requested_tier", data.get("tier", "free"))
    if requested_tier not in TIERS:
        return jsonify({"error": f"Invalid tier. Choose from {list(TIERS)}."}), 400

    # Paid access is granted only after the separate provider verification flow.
    user = User(
        username   = data["username"],
        email      = data["email"],
        role       = data.get("role", Role.RECORDS_OFFICER),
        department = data.get("department"),
        tier       = "free",
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    AuditLog.write(db.session, user.id, "ADMIN_CREATE_USER",
                   table_affected="users", record_id=user.id)
    return jsonify({"message": "User created on the Free tier.", "user_id": user.id, "requested_tier": requested_tier}), 201


@admin_bp.put("/users/<int:user_id>")
@login_required
@admin_only
def update_user(user_id):
    user = db.get_or_404(User, user_id)
    data = request.get_json(silent=True) or {}

    if "username" in data:
        username = str(data["username"]).strip()
        if not username:
            return jsonify({"error": "Username cannot be blank."}), 400
        if User.query.filter(User.username == username, User.id != user_id).first():
            return jsonify({"error": "Username already taken."}), 409
        user.username = username
    if "email" in data:
        email = str(data["email"]).strip()
        if not email:
            return jsonify({"error": "Email cannot be blank."}), 400
        if User.query.filter(User.email == email, User.id != user_id).first():
            return jsonify({"error": "Email already in use."}), 409
        user.email = email
    if "department" in data:
        user.department = str(data["department"]).strip() or None
    if "role" in data:
        if data["role"] not in Role.ALL:
            return jsonify({"error": f"Invalid role. Must be one of {Role.ALL}."}), 400
        user.role = data["role"]
    if "tier" in data:
        if data["tier"] != user.tier:
            return jsonify({"error": "Use the billing flow to change a user's subscription tier."}), 402
    if "is_active" in data:
        user.is_active = bool(data["is_active"])
    if "mfa_enabled" in data:
        user.mfa_enabled = bool(data["mfa_enabled"])

    db.session.commit()
    AuditLog.write(db.session, current_user.id, "ADMIN_UPDATE_USER",
                   table_affected="users", record_id=user.id,
                   extra={"updated_fields": sorted(list(data.keys()))})
    return jsonify({"message": "User updated."}), 200


@admin_bp.post("/users/<int:user_id>/tier")
@login_required
@admin_only
def upgrade_user_tier(user_id):
    user = db.get_or_404(User, user_id)
    data = request.get_json(silent=True) or {}
    new_tier = str(data.get("tier", "")).lower()
    billing_period = str(data.get("billing_period", "monthly")).lower()
    provider = str(data.get("provider", current_app.config.get("BILLING_PROVIDER", ""))).lower()
    payment_reference = str(data.get("payment_reference", "")).strip()

    if new_tier not in TIERS or new_tier == "free":
        return jsonify({"error": "Paid Pro or Enterprise tier is required."}), 400
    if billing_period not in {"monthly", "annual"} or provider not in {"stripe", "paynow"} or not payment_reference:
        return jsonify({"error": "A valid billing period, provider, and provider-issued payment reference are required."}), 400

    payment = _verify_payment(provider, payment_reference, new_tier, billing_period)
    if not payment:
        return jsonify({"error": "Payment could not be verified. The user's tier was not changed."}), 402

    Subscription.query.filter_by(user_id=user.id, active=True).update({"active": False})
    days = 365 if billing_period == "annual" else 30
    subscription = Subscription.create_for_user(user, new_tier, days=days, billing_period=billing_period)
    subscription.payment_method = payment["payment_method"]
    subscription.payment_status = payment["payment_status"]
    db.session.add(subscription)
    db.session.commit()
    AuditLog.write(db.session, current_user.id, "ADMIN_SUBSCRIPTION_UPGRADE", table_affected="users", record_id=user.id, extra={"new_tier": new_tier, "billing_period": billing_period, "provider": provider})
    return jsonify({"message": f"{user.username} upgraded to {new_tier} after verified payment.", "tier": new_tier}), 200


@admin_bp.delete("/users/<int:user_id>")
@login_required
@admin_only
def delete_user(user_id):
    if current_user.id == user_id:
        return jsonify({"error": "You cannot remove your own admin account."}), 400

    user = db.get_or_404(User, user_id)
    user.is_active = False
    db.session.commit()
    AuditLog.write(db.session, current_user.id, "ADMIN_DELETE_USER",
                   table_affected="users", record_id=user_id,
                   extra={"deactivated_username": user.username})
    return jsonify({"message": "User deactivated."}), 200


# ─── Audit log ────────────────────────────────────────────────────────────────

@admin_bp.get("/audit")
@login_required
@admin_only
def audit_log():
    page          = int(request.args.get("page", 1))
    action_filter = request.args.get("action")
    query         = AuditLog.query.order_by(AuditLog.id.desc())

    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))

    pagination = query.paginate(page=page, per_page=50, error_out=False)
    latest_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()
    return jsonify(
        {
            "logs": [
                {
                    "id":             e.id,
                    "user_id":        e.user_id,
                    "action":         e.action,
                    "table_affected": e.table_affected,
                    "record_id":      e.record_id,
                    "ip_address":     e.ip_address,
                    "is_break_glass": e.is_break_glass,
                    "timestamp":      e.timestamp,
                    "entry_hash":     e.entry_hash,
                }
                for e in pagination.items
            ],
            "latest_id": latest_entry.id if latest_entry else None,
            "total": pagination.total,
            "page":  page,
            "pages": pagination.pages,
        }
    ), 200


SECURITY_ACTIONS = {
    "LOGIN_FAILED": ("high", "Failed sign-in", "A sign-in attempt was rejected."),
    "MFA_FAILED": ("high", "MFA verification failed", "A multi-factor verification code was rejected."),
    "NEW_DEVICE_SIGN_IN": ("high", "New device signed in", "A user signed in from a device not seen before."),
    "BREAK_GLASS_ACCESS": ("critical", "Break-glass access used", "Emergency access was used to view a protected record."),
    "MFA_ENABLED": ("info", "MFA enabled", "Multi-factor authentication was enabled for an account."),
}


def _activity_item(entry):
    severity, title, message = SECURITY_ACTIONS[entry.action]
    details = {}
    if entry.extra:
        try:
            details = json.loads(entry.extra)
        except (TypeError, ValueError):
            details = {}
    if entry.action == "BREAK_GLASS_ACCESS" and details.get("reason"):
        message = f"Emergency access was used: {details['reason']}"
    elif entry.action in {"LOGIN_FAILED", "MFA_FAILED"}:
        message = f"{message} Review the source and account activity."

    return {
        "id": entry.id,
        "severity": severity,
        "title": title,
        "message": message,
        "actor": entry.user.username if entry.user else f"User {entry.user_id}",
        "ip_address": entry.ip_address,
        "timestamp": entry.timestamp,
        "is_unread": True,
    }


@admin_bp.get("/security-activity")
@login_required
def security_activity():
    seen_at = current_user.security_activity_seen_at
    activity_query = AuditLog.query.filter(AuditLog.action.in_(SECURITY_ACTIONS))
    if current_user.role != Role.ADMIN:
        activity_query = activity_query.filter(AuditLog.user_id == current_user.id)
    events = []
    for entry in (
        activity_query
        .order_by(AuditLog.id.desc())
        .limit(100)
        .all()
    ):
        item = _activity_item(entry)
        event_time = datetime.fromisoformat(entry.timestamp)
        item["is_unread"] = seen_at is None or event_time > seen_at
        events.append(item)

    if not current_user.mfa_enabled:
        events.insert(0, {
            "id": "mfa-reminder",
            "severity": "warning",
            "title": "MFA setup recommended",
            "message": "Protect this administrator account by enabling multi-factor authentication.",
            "actor": current_user.username,
            "ip_address": None,
            "timestamp": None,
            "is_unread": True,
        })

    return jsonify({
        "events": events,
        "unread_count": sum(event["is_unread"] for event in events),
    }), 200


@admin_bp.post("/security-activity/mark-read")
@login_required
def mark_security_activity_read():
    current_user.security_activity_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    return jsonify({"message": "Security activity marked as read."}), 200


@admin_bp.get("/audit/verify-chain")
@login_required
@admin_only
def verify_chain():
    intact, broken_at = AuditLog.verify_chain(db.session)
    if intact:
        count = AuditLog.query.count()
        return jsonify(
            {
                "status":  "intact",
                "message": f"All {count} audit log entries verified. No tampering detected.",
            }
        ), 200
    return jsonify(
        {
            "status":    "COMPROMISED",
            "message":   f"Hash chain broken at entry id={broken_at}. Possible tampering detected!",
            "broken_at": broken_at,
        }
    ), 200


@admin_bp.delete("/audit/<int:log_id>")
@login_required
@admin_only
def delete_audit_log(log_id):
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password or not current_user.check_password(password):
        return jsonify({"error": "A valid admin password is required."}), 401

    entry = db.get_or_404(AuditLog, log_id)
    latest_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()
    if latest_entry.id != entry.id:
        return jsonify(
            {"error": "Only the newest audit log can be removed to preserve chain integrity."}
        ), 409

    deleted_action = entry.action
    deleted_record_id = entry.record_id
    db.session.delete(entry)
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "ADMIN_DELETE_AUDIT_LOG",
        table_affected="audit_logs", record_id=log_id,
        extra={"deleted_action": deleted_action, "deleted_record_id": deleted_record_id},
    )
    return jsonify({"message": "Audit log removed."}), 200


# ─── Dashboard stats ──────────────────────────────────────────────────────────

@admin_bp.get("/stats")
@login_required
@admin_only
def stats():
    from ..models.patient import Patient
    from ..models.subscription import Subscription

    tier_counts = {tier: User.query.filter_by(tier=tier).count() for tier in TIERS}

    recent_break_glass = AuditLog.query.filter_by(is_break_glass=True).count()
    today = datetime.now(timezone.utc).date()
    trend_dates = [today - timedelta(days=offset) for offset in range(29, -1, -1)]
    trend_keys = {day.isoformat(): 0 for day in trend_dates}

    record_growth = trend_keys.copy()
    for record in MedicalRecord.query.with_entities(MedicalRecord.created_at).all():
        if record.created_at:
            day_key = record.created_at.date().isoformat()
            if day_key in record_growth:
                record_growth[day_key] += 1

    break_glass_trends = trend_keys.copy()
    for event in AuditLog.query.filter_by(is_break_glass=True).with_entities(AuditLog.timestamp).all():
        try:
            day_key = datetime.fromisoformat(event.timestamp).date().isoformat()
        except (TypeError, ValueError):
            continue
        if day_key in break_glass_trends:
            break_glass_trends[day_key] += 1

    return jsonify(
        {
            "total_users":         User.query.count(),
            "total_patients":      Patient.query.count(),
            "total_records":       MedicalRecord.query.count(),
            "total_audit_entries": AuditLog.query.count(),
            "users_by_tier":       tier_counts,
            "break_glass_events":  recent_break_glass,
            "record_growth":       [{"date": day, "count": count} for day, count in record_growth.items()],
            "break_glass_trends":  [{"date": day, "count": count} for day, count in break_glass_trends.items()],
        }
    ), 200
