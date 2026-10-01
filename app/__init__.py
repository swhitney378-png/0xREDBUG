"""
Flask application factory.

Usage:
    from app import create_app
    app = create_app()          # uses DevelopmentConfig by default
"""
import secrets
import os

from flask import Flask
from sqlalchemy import inspect, text
from .config import DevelopmentConfig
from .extensions import csrf, db, limiter, login_manager


def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialise extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.records import records_bp
    from .routes.subscriptions import subscriptions_bp
    from .routes.admin import admin_bp
    from .routes.privacy import privacy_bp
    from .routes.health import health_bp
    from .routes.maintenance import maintenance_bp
    from .routes.integrations import integrations_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(records_bp)
    app.register_blueprint(subscriptions_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(privacy_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(maintenance_bp)
    app.register_blueprint(integrations_bp)

    # User loader — uses SQLAlchemy 2.x Session.get() API
    from .models.user import User, Role
    from .models.subscription import Subscription

    @login_manager.user_loader
    def load_user(user_id):
        user = db.session.get(User, int(user_id))
        if not user or user.tier == "free":
            return user

        subscriptions = (
            Subscription.query
            .filter_by(user_id=user.id, active=True)
            .order_by(Subscription.started_at.desc())
            .all()
        )
        if not subscriptions:
            return user

        now_active = next((sub for sub in subscriptions if sub.is_active()), None)
        changed = False
        for subscription in subscriptions:
            if not subscription.is_active():
                subscription.active = False
                changed = True

        resolved_tier = now_active.tier if now_active else "free"
        if user.tier != resolved_tier:
            user.tier = resolved_tier
            changed = True
        if changed:
            db.session.commit()
        return user

    # Security headers on every response
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # HSTS only makes sense over HTTPS — omit in dev to avoid confusion
        if not app.debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

    # Create tables (idempotent)
    with app.app_context():
        db.create_all()

        # Keep the development database compatible with the current Patient model.
        # db.create_all() does not add columns to tables that already exist.
        from .models.patient import Patient

        existing_columns = {
            column["name"] for column in inspect(db.engine).get_columns("patients")
        }
        with db.engine.begin() as connection:
            for column in Patient.__table__.columns:
                if column.name not in existing_columns:
                    column_type = column.type.compile(dialect=db.engine.dialect)
                    connection.execute(
                        text(f"ALTER TABLE patients ADD COLUMN {column.name} {column_type}")
                    )
            connection.execute(
                text(
                    "UPDATE patients SET patient_code = "
                    "'PT-' || upper(hex(randomblob(5))) "
                    "WHERE patient_code IS NULL"
                )
            )

        existing_record_columns = {
            column["name"] for column in inspect(db.engine).get_columns("medical_records")
        }
        with db.engine.begin() as connection:
            if "key_version" not in existing_record_columns:
                connection.execute(text("ALTER TABLE medical_records ADD COLUMN key_version INTEGER"))

        from .models.user import User

        existing_user_columns = {
            column["name"] for column in inspect(db.engine).get_columns("users")
        }
        with db.engine.begin() as connection:
            for column in User.__table__.columns:
                if column.name not in existing_user_columns:
                    column_type = column.type.compile(dialect=db.engine.dialect)
                    connection.execute(
                        text(f"ALTER TABLE users ADD COLUMN {column.name} {column_type}")
                    )
            connection.execute(
                text("UPDATE users SET mfa_failed_attempts = 0 WHERE mfa_failed_attempts IS NULL")
            )

        existing_subscription_columns = {
            column["name"] for column in inspect(db.engine).get_columns("subscriptions")
        }
        subscription_columns = {
            "billing_period": "VARCHAR(20)",
            "amount_usd": "FLOAT",
            "currency": "VARCHAR(3)",
            "payment_status": "VARCHAR(20)",
            "payment_method": "VARCHAR(80)",
            "invoice_number": "VARCHAR(40)",
            "paid_at": "DATETIME",
        }
        with db.engine.begin() as connection:
            for column_name, column_type in subscription_columns.items():
                if column_name not in existing_subscription_columns:
                    connection.execute(text(f"ALTER TABLE subscriptions ADD COLUMN {column_name} {column_type}"))

                # API keys are created lazily by the integrations page, but the table
                # must exist before its first request in an existing development DB.
                from .models.api_key import ApiKey  # noqa: F401
                db.create_all()

        existing_user_columns = {
            column["name"] for column in inspect(db.engine).get_columns("users")
        }
        with db.engine.begin() as connection:
            for column_name, column_type in {
                "security_activity_seen_at": "DATETIME",
                "last_login_user_agent": "TEXT",
            }.items():
                if column_name not in existing_user_columns:
                    connection.execute(text(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}"))

        # Disable the legacy seeded account so its former password cannot be reused.
        legacy_admin = User.query.filter_by(username="0xRedBug").first()
        if legacy_admin and legacy_admin.is_active:
            legacy_admin.is_active = False
            legacy_admin.set_password(secrets.token_urlsafe(32))
            db.session.commit()

        if not app.testing:
            from .services.maintenance import start_maintenance_scheduler

            start_maintenance_scheduler(app)

        # Provision an admin only when both values are explicitly supplied.
        admin_username = os.environ.get("VAULTWARD_ADMIN_USERNAME")
        admin_password = os.environ.get("VAULTWARD_ADMIN_PASSWORD")
        if admin_username and admin_password:
            admin_email = os.environ.get("VAULTWARD_ADMIN_EMAIL", f"{admin_username}@localhost")
            admin = User.query.filter_by(username=admin_username).first()
            if not admin:
                admin = User.query.filter_by(email=admin_email).first()
            if not admin:
                admin = User(
                    username=admin_username,
                    email=admin_email,
                    role=Role.ADMIN,
                    tier="enterprise",
                    is_active=True,
                )
                db.session.add(admin)
            else:
                admin.username = admin_username
                admin.email = admin_email
            admin.role = Role.ADMIN
            admin.is_active = True
            admin.set_password(admin_password)
            db.session.commit()

    return app
