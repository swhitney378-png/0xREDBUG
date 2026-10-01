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
        "DATABASE_URL", f"sqlite:///{os.path.join(basedir, '..', 'vaultward_dev.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False   # set True only behind HTTPS in production
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_TIME_LIMIT = 3600
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # Payment provider credentials are injected by the deployment environment.
    BILLING_PROVIDER = os.environ.get("VAULTWARD_BILLING_PROVIDER", "").strip().lower()
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
    PAYNOW_INTEGRATION_ID = os.environ.get("PAYNOW_INTEGRATION_ID", "")
    PAYNOW_INTEGRATION_KEY = os.environ.get("PAYNOW_INTEGRATION_KEY", "")
    BILLING_TEST_MODE = os.environ.get("VAULTWARD_BILLING_TEST_MODE", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }

    BACKUP_DIR = os.environ.get(
        "VAULTWARD_BACKUP_DIR",
        os.path.join(basedir, "..", "backups"),
    )
    KEY_ROTATION_INTERVAL_DAYS = {
        "pro": int(os.environ.get("PRO_KEY_ROTATION_DAYS", "90")),
        "enterprise": int(os.environ.get("ENTERPRISE_KEY_ROTATION_DAYS", "30")),
    }
    MAINTENANCE_INTERVAL_SECONDS = int(
        os.environ.get("MAINTENANCE_INTERVAL_SECONDS", "3600")
    )
    MAINTENANCE_RUN_ON_STARTUP = os.environ.get(
        "MAINTENANCE_RUN_ON_STARTUP", "true"
    ).strip().lower() in {"1", "true", "yes", "on"}
    ENABLE_MAINTENANCE_SCHEDULER = os.environ.get(
        "ENABLE_MAINTENANCE_SCHEDULER", "false"
    ).strip().lower() in {"1", "true", "yes", "on"}

    # Lockout policy
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

    # Privacy retention policy
    RECORD_RETENTION_YEARS = int(os.environ.get("RECORD_RETENTION_YEARS", "7"))

    # Tier -> encryption capability map.
    # "free" still uses real AES (AES-128), not 3DES —
    # 3DES is deprecated by NIST as of 2023.
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


class DevelopmentConfig(Config):
    DEBUG = os.environ.get("VAULTWARD_DEBUG", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    ENABLE_MAINTENANCE_SCHEDULER = os.environ.get(
        "ENABLE_MAINTENANCE_SCHEDULER", "true"
    ).strip().lower() in {"1", "true", "yes", "on"}
    SESSION_COOKIE_SECURE = False   # HTTP is fine in dev


class ProductionConfig(Config):
    DEBUG = False
    ENABLE_MAINTENANCE_SCHEDULER = False
    SESSION_COOKIE_SECURE = True    # enforce HTTPS in prod

    # The deployment platform must inject these from its secret manager before
    # importing the application. This app never reads production secrets from a file.
    if not os.environ.get("VAULTWARD_MASTER_SECRET"):
        raise RuntimeError(
            "VAULTWARD_MASTER_SECRET must be injected by the production secret manager."
        )
