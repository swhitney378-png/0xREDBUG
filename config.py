import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY is not set. Add it to your .env file or environment before starting the app."
        )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://localhost/vaultward"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True  # requires HTTPS in production
    SESSION_COOKIE_SAMESITE = "Lax"

    # Lockout policy
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

    # Tier -> encryption capability map.
    # "free" intentionally still uses real AES (AES-128), not 3DES —
    # 3DES is deprecated by NIST as of 2023 and shouldn't protect real
    # medical data even on a free tier. The tier differentiation is in
    # key strength, key rotation, and audit features, not in shipping
    # broken crypto to non-paying users.
    TIER_ENCRYPTION = {
        "free": {
            "algorithm": "AES-128-GCM",
            "key_rotation_days": None,
            "audit_hash_chain": False,
        },
        "pro": {
            "algorithm": "AES-256-GCM",
            "key_rotation_days": 90,
            "audit_hash_chain": True,
        },
        "enterprise": {
            "algorithm": "AES-256-GCM",
            "key_rotation_days": 30,
            "audit_hash_chain": True,
            "hsm_backed": True,
        },
    }
