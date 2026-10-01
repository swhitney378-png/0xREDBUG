import hashlib
import secrets
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

from ..extensions import db
from ..models.api_key import ApiKey
from ..models.audit import AuditLog

integrations_bp = Blueprint("integrations", __name__, url_prefix="/integrations")


def _provider_status():
    return {
        "stripe": {
            "configured": bool(current_app.config.get("STRIPE_SECRET_KEY")),
            "mode": "test" if str(current_app.config.get("STRIPE_SECRET_KEY", "")).startswith("sk_test_") else "live",
        },
        "paynow": {
            "configured": bool(current_app.config.get("PAYNOW_INTEGRATION_ID") and current_app.config.get("PAYNOW_INTEGRATION_KEY")),
            "mode": "configured",
        },
    }


@integrations_bp.get("")
@login_required
def integrations_status():
    return jsonify({
        "providers": _provider_status(),
        "billing_provider": current_app.config.get("BILLING_PROVIDER") or None,
        "api_keys": [key.as_dict() for key in ApiKey.query.filter_by(user_id=current_user.id).order_by(ApiKey.created_at.desc()).all()],
    })


@integrations_bp.post("/api-keys")
@login_required
def create_api_key():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    scopes = data.get("scopes") or ["records:read"]
    allowed_scopes = {"records:read", "records:write", "patients:read"}
    if not name or len(name) > 80:
        return jsonify({"error": "A key name between 1 and 80 characters is required."}), 400
    if not isinstance(scopes, list) or not scopes or not set(scopes).issubset(allowed_scopes):
        return jsonify({"error": "Scopes must be selected from the supported scopes."}), 400

    secret = "vw_live_" + secrets.token_urlsafe(30)
    key = ApiKey(
        user_id=current_user.id,
        name=name,
        key_prefix=secret[:16],
        key_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        scopes=",".join(scopes),
    )
    db.session.add(key)
    db.session.commit()
    AuditLog.write(db.session, current_user.id, "API_KEY_CREATED", extra={"name": name, "scopes": scopes}, ip_address=request.remote_addr)
    return jsonify({"message": "API key created. Copy it now; it will not be shown again.", "key": secret, "details": key.as_dict()}), 201


@integrations_bp.post("/api-keys/<int:key_id>/revoke")
@login_required
def revoke_api_key(key_id):
    key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    if not key:
        return jsonify({"error": "API key not found."}), 404
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()
        AuditLog.write(db.session, current_user.id, "API_KEY_REVOKED", extra={"key_prefix": key.key_prefix}, ip_address=request.remote_addr)
    return jsonify({"message": "API key revoked."})