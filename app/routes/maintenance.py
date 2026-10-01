from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

from ..crypto.rotation import rotate_tier_keys
from ..extensions import db
from ..models.audit import AuditLog
from ..models.user import Role
from ..services.backup import create_encrypted_backup, restore_encrypted_backup
from ..utils.decorators import admin_only

maintenance_bp = Blueprint("maintenance", __name__, url_prefix="/admin/maintenance")


@maintenance_bp.get("/backups")
@login_required
def list_backups():
    backup_dir = Path(current_app.config["BACKUP_DIR"])
    backups = []
    if backup_dir.is_dir():
        for path in sorted(
            backup_dir.glob("*.vwb"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        ):
            stat = path.stat()
            backups.append({
                "filename": path.name,
                "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "size_bytes": stat.st_size,
            })
    return jsonify({
        "backup_directory": str(backup_dir),
        "last_backup": backups[0] if backups else None,
        "backups": backups,
    }), 200


@maintenance_bp.post("/backup")
@login_required
@admin_only
def create_backup():
    path = create_encrypted_backup(db.engine, current_app.config["BACKUP_DIR"])
    AuditLog.write(db.session, current_user.id, "BACKUP_CREATED", table_affected="database", extra={"filename": path.name})
    return jsonify({"message": "Encrypted backup created.", "filename": path.name}), 201


@maintenance_bp.post("/restore")
@login_required
@admin_only
def restore_backup():
    data = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()
    if not filename or filename != __import__("pathlib").Path(filename).name:
        return jsonify({"error": "A backup filename is required."}), 400
    path = __import__("pathlib").Path(current_app.config["BACKUP_DIR"]) / filename
    if not path.is_file():
        return jsonify({"error": "Backup file not found."}), 404
    db.session.remove()
    result = restore_encrypted_backup(db.engine, path)
    AuditLog.write(db.session, current_user.id, "BACKUP_RESTORED", table_affected="database", extra={"filename": filename})
    return jsonify(result), 200


@maintenance_bp.post("/rotate-keys")
@login_required
@admin_only
def rotate_keys():
    data = request.get_json(silent=True) or {}
    tier = data.get("tier")
    tiers = [tier] if tier else ["pro", "enterprise"]
    if any(item not in {"pro", "enterprise"} for item in tiers):
        return jsonify({"error": "tier must be pro or enterprise."}), 400
    results = [rotate_tier_keys(db.session, item) for item in tiers]
    for result in results:
        AuditLog.write(db.session, current_user.id, "KEY_ROTATION_COMPLETED", table_affected="medical_records", extra=result)
    return jsonify({"results": results}), 200
