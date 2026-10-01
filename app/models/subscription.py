from datetime import datetime, timedelta, timezone
from uuid import uuid4
from ..extensions import db

def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

TIERS = {
    "free": {
        "label":        "Free",
        "algorithm":    "AES-128-GCM",
        "key_rotation": None,
        "audit_chain":  False,
        "price_usd":    0,
        "monthly_price_usd": 0,
        "annual_price_usd":  0,
        "annual_discount_percent": 0,
        "annual_free_months": 0,
        "billing_unit": "organization",
        "limited_access": True,
    },
    "pro": {
        "label":        "Pro",
        "algorithm":    "AES-256-GCM",
        "key_rotation": 90,    # days
        "audit_chain":  True,
        "price_usd":    14.99,
        "monthly_price_usd": 14.99,
        "annual_price_usd":  149.99,
        "annual_discount_percent": 17,
        "annual_free_months": 2,
        "billing_unit": "organization",
        "limited_access": False,
    },
    "enterprise": {
        "label":        "Enterprise",
        "algorithm":    "AES-256-GCM",
        "key_rotation": 30,
        "audit_chain":  True,
        "hsm_backed":   True,
        "price_usd":    49.99,
        "monthly_price_usd": 49.99,
        "annual_price_usd":  499.99,
        "annual_discount_percent": 17,
        "annual_free_months": 2,
        "billing_unit": "organization",
        "limited_access": False,
    },
}


class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tier       = db.Column(db.String(20), nullable=False, default="free")
    started_at = db.Column(db.DateTime, default=utc_now_naive)
    expires_at = db.Column(db.DateTime, nullable=True)   # None = indefinite (enterprise)
    active     = db.Column(db.Boolean,  default=True)
    billing_period = db.Column(db.String(20), nullable=True, default="monthly")
    amount_usd = db.Column(db.Float, nullable=True, default=0)
    currency = db.Column(db.String(3), nullable=True, default="USD")
    payment_status = db.Column(db.String(20), nullable=True, default="paid")
    payment_method = db.Column(db.String(80), nullable=True, default="Simulated checkout")
    invoice_number = db.Column(db.String(40), unique=True, nullable=True, default=lambda: f"VW-{uuid4().hex[:12].upper()}")
    paid_at = db.Column(db.DateTime, default=utc_now_naive)

    user = db.relationship("User", back_populates="subscriptions")

    __table_args__ = (
        db.Index("ix_subscriptions_user_active_started", "user_id", "active", "started_at"),
    )

    def is_active(self) -> bool:
        if not self.active:
            return False
        if self.expires_at and self.expires_at < utc_now_naive():
            return False
        return True

    @staticmethod
    def create_for_user(user, tier: str, days: "int | None" = 30, billing_period: str = "monthly"):
        sub = Subscription(
            user_id=user.id,
            tier=tier,
            expires_at=utc_now_naive() + timedelta(days=days) if days else None,
            billing_period=billing_period,
            amount_usd=TIERS.get(tier, TIERS["free"])[f"{billing_period}_price_usd"],
        )
        # Sync the user's active tier field
        user.tier = tier
        return sub

    def tier_info(self) -> dict:
        return TIERS.get(self.tier, TIERS["free"])

    def billing_dict(self) -> dict:
        return {
            "id": self.id,
            "invoice_number": self.invoice_number or f"VW-HISTORY-{self.id}",
            "tier": self.tier,
            "tier_label": self.tier_info()["label"],
            "billing_period": self.billing_period or "monthly",
            "amount": self.amount_usd or 0,
            "currency": self.currency or "USD",
            "payment_status": self.payment_status or ("paid" if self.tier != "free" else "included"),
            "payment_method": self.payment_method or "No payment method on file",
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "renewal_date": self.expires_at.isoformat() if self.expires_at else None,
            "active": self.is_active(),
        }

    def __repr__(self):
        return f"<Subscription user={self.user_id} tier={self.tier}>"
