import threading
from datetime import datetime, timedelta

from ..crypto.rotation import ROTATING_TIERS, rotate_tier_keys
from ..models.key_version import KeyVersion
from .backup import create_encrypted_backup


def _due_key_rotations(session, now: datetime, intervals: dict) -> list[str]:
    due = []
    for tier in ROTATING_TIERS:
        active = session.query(KeyVersion).filter_by(tier=tier, active=True).first()
        if not active or active.created_at <= now - timedelta(days=intervals[tier]):
            due.append(tier)
    return due


def run_maintenance(app) -> dict:
    from ..extensions import db

    results = {"backup": None, "rotations": []}
    with app.app_context():
        results["backup"] = str(create_encrypted_backup(db.engine, app.config["BACKUP_DIR"]))
        intervals = app.config["KEY_ROTATION_INTERVAL_DAYS"]
        for tier in _due_key_rotations(db.session, datetime.utcnow(), intervals):
            result = rotate_tier_keys(db.session, tier)
            results["rotations"].append(result)
    return results


def start_maintenance_scheduler(app) -> None:
    if not app.config.get("ENABLE_MAINTENANCE_SCHEDULER", True):
        return
    if app.extensions.get("vaultward_maintenance_started"):
        return
    app.extensions["vaultward_maintenance_started"] = True

    def worker():
        first_run = True
        while True:
            try:
                if first_run or app.config["MAINTENANCE_RUN_ON_STARTUP"]:
                    run_maintenance(app)
                    first_run = False
            except Exception:
                app.logger.exception("VaultWard maintenance run failed")
            interval = app.config["MAINTENANCE_INTERVAL_SECONDS"]
            threading.Event().wait(interval)

    thread = threading.Thread(target=worker, name="vaultward-maintenance", daemon=True)
    thread.start()
