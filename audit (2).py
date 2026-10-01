"""
Hash-chained audit log.

Every entry stores:
  - prev_hash  — hash of the previous entry (or "GENESIS" for the first)
  - entry_hash — SHA-256 of (prev_hash + user_id + action + table + timestamp)

To detect tampering: re-compute each hash from scratch and compare.
Any edited or deleted row breaks every subsequent link.
"""
import hashlib
import json
from datetime import datetime
from ..extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action          = db.Column(db.String(100), nullable=False)  # e.g. "CREATE_RECORD"
    table_affected  = db.Column(db.String(60))
    record_id       = db.Column(db.Integer, nullable=True)
    ip_address      = db.Column(db.String(45))
    extra           = db.Column(db.Text)           # JSON blob for any extra context
    is_break_glass  = db.Column(db.Boolean, default=False)

    timestamp       = db.Column(db.String(32), nullable=False)   # ISO-8601 string, not DateTime
    prev_hash       = db.Column(db.String(64), nullable=False)
    entry_hash      = db.Column(db.String(64), nullable=False, unique=True)

    user            = db.relationship("User", back_populates="audit_logs")

    @staticmethod
    def _compute_hash(prev_hash, user_id, action, table_affected, timestamp) -> str:
        payload = json.dumps({
            "prev_hash":      prev_hash,
            "user_id":        user_id,
            "action":         action,
            "table_affected": table_affected,
            "timestamp":      timestamp,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    @classmethod
    def write(cls, db_session, user_id: int, action: str,
              table_affected: str = None, record_id: int = None,
              ip_address: str = None, extra: dict = None,
              is_break_glass: bool = False):
        """Create and persist a new chained audit log entry."""
        last = db_session.query(cls).order_by(cls.id.desc()).first()
        prev_hash = last.entry_hash if last else "GENESIS"
        timestamp = datetime.utcnow().isoformat()

        entry_hash = cls._compute_hash(prev_hash, user_id, action, table_affected, timestamp)

        log = cls(
            user_id=user_id,
            action=action,
            table_affected=table_affected,
            record_id=record_id,
            ip_address=ip_address,
            extra=json.dumps(extra) if extra else None,
            is_break_glass=is_break_glass,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        db_session.add(log)
        db_session.commit()
        return log

    @classmethod
    def verify_chain(cls, db_session) -> tuple[bool, int | None]:
        """
        Walk every entry in order and recompute hashes.
        Returns (True, None) if intact or (False, first_broken_id) if tampered.
        """
        entries = db_session.query(cls).order_by(cls.id.asc()).all()
        prev_hash = "GENESIS"
        for entry in entries:
            expected = cls._compute_hash(
                prev_hash, entry.user_id, entry.action,
                entry.table_affected, entry.timestamp
            )
            if expected != entry.entry_hash:
                return False, entry.id
            prev_hash = entry.entry_hash
        return True, None

    def __repr__(self):
        return f"<AuditLog {self.id} [{self.action}] user={self.user_id}>"
