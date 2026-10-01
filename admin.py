"""
Admin routes (admin role only):
  GET  /admin/users               — list all users
  POST /admin/users               — create a user
  PUT  /admin/users/<id>          — update role / tier / status
  GET  /admin/audit               — view audit log (paginated)
  GET  /admin/audit/verify-chain  — verify audit hash chain integrity
  GET  /admin/stats               — dashboard summary stats
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required
from ..extensions import db
from ..models.user import User, Role
from ..models.audit import AuditLog
from ..models.patient import MedicalRecord
from ..models.subscription import TIERS
from ..utils.decorators import admin_only

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ─── Users ────────────────────────────────────────────────────────────────────

@admin_bp.get("/users")
@login_required
@admin_only
def list_users():
    users = User.query.order_by(User.id).all()
    return jsonify([{
        "id":         u.id,
        "username":   u.username,
        "email":      u.email,
        "role":       u.role,
        "tier":       u.tier,
        "is_active":  u.is_active,
        "mfa_enabled":u.mfa_enabled,
        "created_at": u.created_at.isoformat(),
    } for u in users]), 200


@admin_bp.post("/users")
@login_required
@admin_only
def create_user():
    data = request.get_json(silent=True) or {}
    required = ["username", "email", "password"]
    if not all(data.get(f) for f in required):
        return jsonify({"error": "username, email and password required."}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already taken."}), 409

    if data.get("role") not in Role.ALL:
        return jsonify({"error": f"role must be one of {Role.ALL}."}), 400

    user = User(
        username   = data["username"],
        email      = data["email"],
        role       = data.get("role", Role.RECORDS_OFFICER),
        department = data.get("department"),
        tier       = data.get("tier", "free"),
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    AuditLog.write(db.session, user.id, "ADMIN_CREATE_USER",
                   table_affected="users", record_id=user.id)
    return jsonify({"message": "User created.", "user_id": user.id}), 201


@admin_bp.put("/users/<int:user_id>")
@login_required
@admin_only
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}

    if "role" in data:
        if data["role"] not in Role.ALL:
            return jsonify({"error": f"Invalid role. Must be one of {Role.ALL}."}), 400
        user.role = data["role"]
    if "tier" in data:
        if data["tier"] not in TIERS:
            return jsonify({"error": f"Invalid tier. Choose from {list(TIERS)}."}), 400
        user.tier = data["tier"]
    if "is_active" in data:
        user.is_active = bool(data["is_active"])

    db.session.commit()
    return jsonify({"message": "User updated."}), 200


# ─── Audit log ────────────────────────────────────────────────────────────────

@admin_bp.get("/audit")
@login_required
@admin_only
def audit_log():
    page        = int(request.args.get("page", 1))
    action_filter = request.args.get("action")
    query       = AuditLog.query.order_by(AuditLog.id.desc())

    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))

    pagination  = query.paginate(page=page, per_page=50, error_out=False)
    return jsonify({
        "logs": [{
            "id":             e.id,
            "user_id":        e.user_id,
            "action":         e.action,
            "table_affected": e.table_affected,
            "record_id":      e.record_id,
            "ip_address":     e.ip_address,
            "is_break_glass": e.is_break_glass,
            "timestamp":      e.timestamp,
            "entry_hash":     e.entry_hash,
        } for e in pagination.items],
        "total": pagination.total,
        "page":  page,
        "pages": pagination.pages,
    }), 200


@admin_bp.get("/audit/verify-chain")
@login_required
@admin_only
def verify_chain():
    intact, broken_at = AuditLog.verify_chain(db.session)
    if intact:
        count = AuditLog.query.count()
        return jsonify({
            "status":  "intact",
            "message": f"All {count} audit log entries verified. No tampering detected.",
        }), 200
    return jsonify({
        "status":     "COMPROMISED",
        "message":    f"Hash chain broken at entry id={broken_at}. Possible tampering detected!",
        "broken_at":  broken_at,
    }), 200


# ─── Dashboard stats ──────────────────────────────────────────────────────────

@admin_bp.get("/stats")
@login_required
@admin_only
def stats():
    from ..models.patient import Patient
    from ..models.subscription import Subscription

    tier_counts = {}
    for tier in TIERS:
        tier_counts[tier] = User.query.filter_by(tier=tier).count()

    recent_break_glass = AuditLog.query.filter_by(is_break_glass=True).count()

    return jsonify({
        "total_users":         User.query.count(),
        "total_patients":      Patient.query.count(),
        "total_records":       MedicalRecord.query.count(),
        "total_audit_entries": AuditLog.query.count(),
        "users_by_tier":       tier_counts,
        "break_glass_events":  recent_break_glass,
    }), 200
