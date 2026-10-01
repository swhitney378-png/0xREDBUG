"""
Authentication routes:
  POST /auth/login        — username + password, returns session + MFA prompt
  POST /auth/mfa-verify   — TOTP code verification, completes login
  POST /auth/logout       — clears session
  GET  /auth/mfa-setup    — generate a new MFA secret for the current user
  POST /auth/mfa-setup    — confirm and activate MFA
"""
import json
try:
    import qrcode
    from qrcode.image.svg import SvgPathImage
except ImportError:
    qrcode = None
    SvgPathImage = None
import pyotp
from flask import Blueprint, request, jsonify, session, render_template, redirect
from flask_login import login_user, logout_user, login_required, current_user
from ..extensions import db
from ..models.user import User
from ..models.audit import AuditLog
from ..config import DevelopmentConfig as Config
from ..extensions import limiter

auth_bp = Blueprint("auth", __name__) # No url_prefix, let's register /auth routes explicitly or keep the routes relative to root/auth


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _record_successful_login(user, action):
    user_agent = request.headers.get("User-Agent", "")
    if user.last_login_user_agent != user_agent:
        AuditLog.write(
            db.session, user.id, "NEW_DEVICE_SIGN_IN", ip_address=_client_ip(),
            extra={"user_agent": user_agent},
        )
    user.last_login_user_agent = user_agent
    db.session.commit()
    AuditLog.write(db.session, user.id, action, ip_address=_client_ip())


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    return render_template("index.html")


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", initial_section=request.args.get("section", "patients"))


@auth_bp.route("/billing")
@login_required
def billing_page():
    return render_template("dashboard.html", initial_section="subscription")


@auth_bp.route("/security-activity")
@login_required
def security_activity_page():
    return render_template("dashboard.html", initial_section="security")


@auth_bp.route("/profile")
@login_required
def profile_page():
    return render_template("dashboard.html", initial_section="profile")


@auth_bp.route("/reports")
@login_required
def reports_page():
    return render_template("dashboard.html", initial_section="analytics")


@auth_bp.route("/consent")
@login_required
def consent_page():
    return render_template("dashboard.html", initial_section="consent")


@auth_bp.route("/backups")
@login_required
def backups_page():
    return render_template("dashboard.html", initial_section="backups")


# ─── Login (step 1 of 2) ──────────────────────────────────────────────────────
@auth_bp.route("/auth/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect("/dashboard")
        return render_template("login.html")

    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.is_active:
        return jsonify({"error": "Invalid credentials."}), 401

    if user.is_locked():
        return jsonify(
            {
                "error": (
                    "Account temporarily locked due to too many failed attempts. "
                    "Try again later."
                )
            }
        ), 423

    if not user.check_password(password):
        user.record_failed_login(
            max_attempts=Config.MAX_LOGIN_ATTEMPTS,
            lockout_minutes=Config.LOCKOUT_MINUTES,
        )
        AuditLog.write(db.session, user.id, "LOGIN_FAILED", ip_address=_client_ip())
        attempts_left = Config.MAX_LOGIN_ATTEMPTS - user.failed_attempts
        return jsonify(
            {
                "error":              "Invalid credentials.",
                "attempts_remaining": max(attempts_left, 0),
            }
        ), 401

    # Correct password — reset lockout counters
    user.reset_login_state()

    # If MFA is enabled, store uid in session and demand the TOTP code
    if user.mfa_enabled:
        session["mfa_pending_user_id"] = user.id
        return jsonify({"mfa_required": True}), 200

    # No MFA — full login
    login_user(user, remember=False)
    _record_successful_login(user, "LOGIN_SUCCESS")
    return jsonify(
        {
            "message": "Logged in.",
            "user": {
                "id":       user.id,
                "username": user.username,
                "role":     user.role,
                "tier":     user.tier,
            },
        }
    ), 200



# ─── MFA verification (step 2 of 2) ──────────────────────────────────────────
@auth_bp.post("/auth/mfa-verify")
@limiter.limit("5 per minute")
def mfa_verify():
    pending_id = session.get("mfa_pending_user_id")
    if not pending_id:
        return jsonify({"error": "No pending MFA session."}), 400

    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip()

    user = db.session.get(User, pending_id)
    if not user:
        session.pop("mfa_pending_user_id", None)
        return jsonify({"error": "Session expired."}), 401

    if user.is_mfa_locked():
        return jsonify({"error": "MFA temporarily locked. Try again later."}), 423

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        user.record_failed_mfa(
            max_attempts=Config.MAX_LOGIN_ATTEMPTS,
            lockout_minutes=Config.LOCKOUT_MINUTES,
        )
        AuditLog.write(db.session, user.id, "MFA_FAILED", ip_address=_client_ip())
        return jsonify({"error": "Invalid or expired code."}), 401

    user.reset_mfa_state()
    session.pop("mfa_pending_user_id", None)
    login_user(user, remember=False)
    _record_successful_login(user, "LOGIN_SUCCESS_MFA")
    return jsonify(
        {
            "message": "MFA verified. Logged in.",
            "user": {
                "id":       user.id,
                "username": user.username,
                "role":     user.role,
                "tier":     user.tier,
            },
        }
    ), 200


# ─── Logout ───────────────────────────────────────────────────────────────────
@auth_bp.post("/auth/logout")
@login_required
def logout():
    AuditLog.write(db.session, current_user.id, "LOGOUT", ip_address=_client_ip())
    logout_user()
    session.clear()
    return jsonify({"message": "Logged out."}), 200


# ─── Profile and account settings ───────────────────────────────────────────
@auth_bp.get("/auth/profile")
@login_required
def profile():
    sign_ins = AuditLog.query.filter_by(
        user_id=current_user.id, action="NEW_DEVICE_SIGN_IN"
    ).order_by(AuditLog.id.desc()).limit(10).all()
    devices = []
    for entry in sign_ins:
        details = {}
        if entry.extra:
            try:
                details = json.loads(entry.extra)
            except (TypeError, ValueError):
                pass
        devices.append({
            "timestamp": entry.timestamp,
            "ip_address": entry.ip_address,
            "user_agent": details.get("user_agent") or "Unknown browser",
        })

    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "department": current_user.department,
        "tier": current_user.tier,
        "mfa_enabled": bool(current_user.mfa_enabled),
        "devices": devices,
    }), 200


@auth_bp.post("/auth/change-password")
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords are required."}), 400
    if not current_user.check_password(current_password):
        return jsonify({"error": "Current password is incorrect."}), 401
    if len(new_password) < 12:
        return jsonify({"error": "New password must be at least 12 characters."}), 400
    if current_user.check_password(new_password):
        return jsonify({"error": "New password must be different from the current password."}), 400

    current_user.set_password(new_password)
    db.session.commit()
    AuditLog.write(db.session, current_user.id, "PASSWORD_CHANGED", ip_address=_client_ip())
    return jsonify({"message": "Password changed successfully."}), 200


@auth_bp.post("/auth/mfa-disable")
@login_required
def mfa_disable():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    code = data.get("code", "").strip()
    if not current_user.check_password(password):
        return jsonify({"error": "Password is incorrect."}), 401
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        return jsonify({"error": "MFA is already disabled."}), 400
    if not pyotp.TOTP(current_user.mfa_secret).verify(code, valid_window=1):
        return jsonify({"error": "MFA code is invalid or expired."}), 401

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.session.commit()
    AuditLog.write(db.session, current_user.id, "MFA_DISABLED", ip_address=_client_ip())
    return jsonify({"message": "MFA disabled successfully."}), 200


# ─── MFA Setup ────────────────────────────────────────────────────────────────
@auth_bp.get("/auth/mfa-setup")
@login_required
def mfa_setup_get():
    """Generate a TOTP secret and return the provisioning URI for a QR code."""
    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="VaultWard",
    )
    qr_svg = None
    if qrcode is not None:
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_svg = qr.make_image(image_factory=SvgPathImage).to_string().decode("utf-8")
    return jsonify({"secret": secret, "qr_svg": qr_svg}), 200


@auth_bp.post("/auth/mfa-setup")
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

    AuditLog.write(db.session, current_user.id, "MFA_ENABLED", ip_address=_client_ip())
    return jsonify({"message": "MFA enabled successfully."}), 200
