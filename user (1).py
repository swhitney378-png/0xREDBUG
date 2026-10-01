from datetime import datetime, timedelta
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from ..extensions import db

ph = PasswordHasher()


class Role:
    ADMIN          = "admin"
    DOCTOR         = "doctor"
    NURSE          = "nurse"
    RECORDS_OFFICER = "records_officer"
    ALL = [ADMIN, DOCTOR, NURSE, RECORDS_OFFICER]


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id                    = db.Column(db.Integer, primary_key=True)
    username              = db.Column(db.String(80), unique=True, nullable=False)
    email                 = db.Column(db.String(120), unique=True, nullable=False)
    password_hash         = db.Column(db.Text, nullable=False)
    role                  = db.Column(db.String(30), nullable=False, default=Role.RECORDS_OFFICER)
    department            = db.Column(db.String(100))
    is_active             = db.Column(db.Boolean, default=True)

    # MFA
    mfa_secret            = db.Column(db.String(64), nullable=True)
    mfa_enabled           = db.Column(db.Boolean, default=False)

    # Subscription tier  (free / pro / enterprise)
    tier                  = db.Column(db.String(20), nullable=False, default="free")

    # Brute-force lockout
    failed_attempts       = db.Column(db.Integer, default=0)
    locked_until          = db.Column(db.DateTime, nullable=True)

    created_at            = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    records               = db.relationship("MedicalRecord", back_populates="created_by_user", lazy="dynamic")
    audit_logs            = db.relationship("AuditLog", back_populates="user", lazy="dynamic")
    subscriptions         = db.relationship("Subscription", back_populates="user", lazy="dynamic")

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
        return bool(self.locked_until and self.locked_until > datetime.utcnow())

    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
        db.session.commit()

    def reset_login_state(self):
        self.failed_attempts = 0
        self.locked_until    = None
        db.session.commit()

    def __repr__(self):
        return f"<User {self.username} [{self.role}]>"
