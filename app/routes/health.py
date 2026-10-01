from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text

from ..extensions import db
from ..models.key_version import KeyVersion
from ..crypto.rotation import ROTATING_TIERS

health_bp = Blueprint("health", __name__)


@health_bp.get("/healthz")
def healthz():
    checks = {"database": "ok", "encryption": "ok", "maintenance": "ok"}
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        db.session.rollback()
        checks["database"] = "failed"
    try:
        from ..crypto import keys
        if not keys.MASTER_SECRET:
            checks["encryption"] = "failed"
    except Exception:
        checks["encryption"] = "failed"
    try:
        now = datetime.utcnow()
        intervals = current_app.config["KEY_ROTATION_INTERVAL_DAYS"]
        due = []
        for tier in ROTATING_TIERS:
            active = db.session.query(KeyVersion).filter_by(tier=tier, active=True).first()
            if active and active.created_at <= now - timedelta(days=intervals[tier]):
                due.append(tier)
        if due:
            checks["maintenance"] = "due"
    except Exception:
        checks["maintenance"] = "failed"
    status = "ok" if all(value == "ok" for value in checks.values()) else "degraded"
    return jsonify({"status": status, "checks": checks, "timestamp": datetime.utcnow().isoformat()}), (200 if status == "ok" else 503)
