from datetime import datetime, timezone

from ..extensions import db


def utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    key_prefix = db.Column(db.String(16), nullable=False, index=True)
    key_hash = db.Column(db.String(64), nullable=False, unique=True)
    scopes = db.Column(db.Text, nullable=False, default="records:read")
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref=db.backref("api_keys", lazy="select"))

    def is_active(self):
        return self.revoked_at is None

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": self.scopes.split(",") if self.scopes else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "active": self.is_active(),
        }