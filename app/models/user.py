from datetime import datetime, timedelta, timezone
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from ..extensions import db

ph = PasswordHasher()


def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role:
    ADMIN           = "admin"
    DOCTOR          = "doctor"
    NURSE           = "nurse"
    RECORDS_OFFICER = "records_officer"
    ALL = [ADMIN, DOCTOR, NURSE, RECORDS_OFFICER]


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    role          = db.Column(db.String(30), nullable=False, default=Role.RECORDS_OFFICER)
    department    = db.Column(db.String(100))
    is_active     = db.Column(db.Boolean, default=True)

    # MFA
    mfa_secret    = db.Column(db.String(64), nullable=True)
    mfa_enabled   = db.Column(db.Boolean, default=False)

    # Subscription tier  (free / pro / enterprise)
    tier          = db.Column(db.String(20), nullable=False, default="free")

    # Brute-force lockout
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)
    mfa_failed_attempts = db.Column(db.Integer, default=0)
    mfa_locked_until    = db.Column(db.DateTime, nullable=True)
    security_activity_seen_at = db.Column(db.DateTime, nullable=True)
    last_login_user_agent = db.Column(db.Text, nullable=True)

    created_at    = db.Column(db.DateTime, default=utc_now_naive)

    # Relationships — lazy="select" replaces the deprecated lazy="dynamic"
    records       = db.relationship("MedicalRecord", back_populates="created_by_user", lazy="select")
    audit_logs    = db.relationship("AuditLog",      back_populates="user",            lazy="select")
    subscriptions = db.relationship("Subscription",  back_populates="user",            lazy="select")

    def __init__(self, username=None, email=None, role=None, department=None, tier="free", is_active=True, **kwargs):
        super().__init__(
            username=username,
            email=email,
            role=role or Role.RECORDS_OFFICER,
            department=department,
            tier=tier,
            is_active=is_active,
            **kwargs
        )

    # ─── password ─────────────────────────────────────────────────────────────
    def set_password(self, plain: str):
        self.password_hash = ph.hash(plain)

    def check_password(self, plain: str) -> bool:
        try:
            ph.verify(self.password_hash, plain)
            # Re-hash if argon2 params have been upgraded
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(plain)
                db.session.commit()
            return True
        except VerifyMismatchError:
            return False

    # ─── lockout ──────────────────────────────────────────────────────────────
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utc_now_naive())

    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = utc_now_naive() + timedelta(minutes=lockout_minutes)
        db.session.commit()

    def reset_login_state(self):
        self.failed_attempts = 0
        self.locked_until    = None
        db.session.commit()

    def is_mfa_locked(self) -> bool:
        return bool(self.mfa_locked_until and self.mfa_locked_until > utc_now_naive())

    def record_failed_mfa(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.mfa_failed_attempts += 1
        if self.mfa_failed_attempts >= max_attempts:
            self.mfa_locked_until = utc_now_naive() + timedelta(minutes=lockout_minutes)
        db.session.commit()

    def reset_mfa_state(self):
        self.mfa_failed_attempts = 0
        self.mfa_locked_until = None
        db.session.commit()

    def __repr__(self):
        return f"<User {self.username} [{self.role}]>"
