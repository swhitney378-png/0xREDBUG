from datetime import datetime, timedelta
from ..extensions import db

TIERS = {
    "free": {
        "label":        "Free",
        "algorithm":    "AES-128-GCM",
        "key_rotation": None,
        "audit_chain":  False,
        "price_usd":    0,
    },
    "pro": {
        "label":        "Pro",
        "algorithm":    "AES-256-GCM",
        "key_rotation": 90,    # days
        "audit_chain":  True,
        "price_usd":    14.99,
    },
    "enterprise": {
        "label":        "Enterprise",
        "algorithm":    "AES-256-GCM",
        "key_rotation": 30,
        "audit_chain":  True,
        "hsm_backed":   True,
        "price_usd":    49.99,
    },
}


class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tier        = db.Column(db.String(20), nullable=False, default="free")
    started_at  = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at  = db.Column(db.DateTime, nullable=True)   # None = indefinite (enterprise)
    active      = db.Column(db.Boolean,  default=True)

    user        = db.relationship("User", back_populates="subscriptions")

    def is_active(self) -> bool:
        if not self.active:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True

    @staticmethod
    def create_for_user(user, tier: str, days: int | None = 30):
        sub = Subscription(
            user_id=user.id,
            tier=tier,
            expires_at=datetime.utcnow() + timedelta(days=days) if days else None,
        )
        # Sync the user's active tier field
        user.tier = tier
        return sub

    def tier_info(self) -> dict:
        return TIERS.get(self.tier, TIERS["free"])

    def __repr__(self):
        return f"<Subscription user={self.user_id} tier={self.tier}>"
