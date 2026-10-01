from datetime import datetime, timezone

from ..extensions import db


def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class KeyVersion(db.Model):
    __tablename__ = "key_versions"

    id = db.Column(db.Integer, primary_key=True)
    tier = db.Column(db.String(20), nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False)
    wrapped_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    active = db.Column(db.Boolean, default=False, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("tier", "version", name="uq_key_version_tier_version"),
    )
