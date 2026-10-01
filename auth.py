"""
Authentication routes:
  POST /auth/login        — username + password, returns session + MFA prompt
  POST /auth/mfa-verify   — TOTP code verification, completes login
  POST /auth/logout       — clears session
  GET  /auth/mfa-setup    — generate a new MFA secret for the current user
  POST /auth/mfa-setup    — confirm and activate MFA
"""
import pyotp
from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from ..extensions import db
from ..models.user import User
from ..models.audit import AuditLog
from ..config import Config

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr)


# ─── Login (step 1 of 2) ──────────────────────────────────────────────────────
@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.is_active:
        return jsonify({"error": "Invalid credentials."}), 401

    if user.is_locked():
        return jsonify({
            "error": "Account temporarily locked due to too many failed attempts. Try again later."
        }), 423

    if not user.check_password(password):
        user.record_failed_login(
            max_attempts=Config.MAX_LOGIN_ATTEMPTS,
            lockout_minutes=Config.LOCKOUT_MINUTES,
        )
        AuditLog.write(db.session, user.id, "LOGIN_FAILED",
                       ip_address=_client_ip())
        attempts_left = Config.MAX_LOGIN_ATTEMPTS - user.failed_attempts
        return jsonify({
            "error": "Invalid credentials.",
            "attempts_remaining": max(attempts_left, 0),
        }), 401

    # Correct password — reset lockout counters
    user.reset_login_state()

    # If MFA is enabled, store uid in session and demand the TOTP code
    if user.mfa_enabled:
        session["mfa_pending_user_id"] = user.id
        return jsonify({"mfa_required": True}), 200

    # No MFA — full login
    login_user(user, remember=False)
    AuditLog.write(db.session, user.id, "LOGIN_SUCCESS",
                   ip_address=_client_ip())
    return jsonify({
        "message": "Logged in.",
        "user": {
            "id":       user.id,
            "username": user.username,
            "role":     user.role,
            "tier":     user.tier,
        },
    }), 200


# ─── MFA verification (step 2 of 2) ──────────────────────────────────────────
@auth_bp.post("/mfa-verify")
def mfa_verify():
    pending_id = session.get("mfa_pending_user_id")
    if not pending_id:
        return jsonify({"error": "No pending MFA session."}), 400

    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip()

    user = User.query.get(pending_id)
    if not user:
        session.pop("mfa_pending_user_id", None)
        return jsonify({"error": "Session expired."}), 401

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        AuditLog.write(db.session, user.id, "MFA_FAILED",
                       ip_address=_client_ip())
        return jsonify({"error": "Invalid or expired code."}), 401

    session.pop("mfa_pending_user_id", None)
    login_user(user, remember=False)
    AuditLog.write(db.session, user.id, "LOGIN_SUCCESS_MFA",
                   ip_address=_client_ip())
    return jsonify({
        "message": "MFA verified. Logged in.",
        "user": {
            "id": user.id, "username": user.username,
            "role": user.role, "tier": user.tier,
        },
    }), 200


# ─── Logout ───────────────────────────────────────────────────────────────────
@auth_bp.post("/logout")
@login_required
def logout():
    AuditLog.write(db.session, current_user.id, "LOGOUT",
                   ip_address=_client_ip())
    logout_user()
    session.clear()
    return jsonify({"message": "Logged out."}), 200


# ─── MFA Setup ────────────────────────────────────────────────────────────────
@auth_bp.get("/mfa-setup")
@login_required
def mfa_setup_get():
    """Generate a TOTP secret and return the provisioning URI for a QR code."""
    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="VaultWard"
    )
    return jsonify({"secret": secret, "qr_uri": uri}), 200


@auth_bp.post("/mfa-setup")
@login_required
def mfa_setup_post():
    """Confirm TOTP code, then activate MFA on the account."""
    secret = session.get("mfa_setup_secret")
    if not secret:
        return jsonify({"error": "Start MFA setup first (GET /auth/mfa-setup)."}), 400

    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip()

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Code invalid — try again."}), 400

    current_user.mfa_secret  = secret
    current_user.mfa_enabled = True
    db.session.commit()
    session.pop("mfa_setup_secret", None)

    AuditLog.write(db.session, current_user.id, "MFA_ENABLED",
                   ip_address=_client_ip())
    return jsonify({"message": "MFA enabled successfully."}), 200
