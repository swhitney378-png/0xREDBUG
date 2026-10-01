import os
import unittest
from flask import g
import pyotp
from datetime import datetime, timedelta

# Setup dummy master secret for testing BEFORE importing app components
os.environ["VAULTWARD_MASTER_SECRET"] = "0123456789abcdef0123456789abcdef"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app import create_app
from app.extensions import db
from app.models.user import User, Role
from app.models.patient import Patient, MedicalRecord
from app.models.subscription import Subscription
from app.models.audit import AuditLog
from app.crypto.engine import encrypt_for_user, decrypt_for_user


class VaultWardTestCase(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        from app.config import Config
        class TestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            WTF_CSRF_ENABLED = False
            SESSION_COOKIE_SECURE = False
            BILLING_TEST_MODE = True

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        db.create_all()

        # Seed initial admin user
        self.admin = User(
            username="admin_test",
            email="admin@vaultward.local",
            role=Role.ADMIN,
            tier="free"
        )
        self.admin.set_password("AdminPass123!")
        db.session.add(self.admin)

        # Seed initial doctor user
        self.doctor = User(
            username="doctor_test",
            email="doctor@vaultward.local",
            role=Role.DOCTOR,
            tier="pro"
        )
        self.doctor.set_password("DoctorPass123!")
        db.session.add(self.doctor)

        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_login_success_no_mfa(self):
        """Test successful login with username and password when MFA is disabled."""
        response = self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("message", data)
        self.assertEqual(data["user"]["username"], "doctor_test")
        self.assertFalse(data.get("mfa_required", False))

    def test_login_failed_increment_lockout(self):
        """Test that failed login increments attempts and eventually locks account."""
        # Attempt 1-5 fail
        for i in range(5):
            response = self.client.post('/auth/login', json={
                "username": "doctor_test",
                "password": "WrongPassword!"
            })
            self.assertEqual(response.status_code, 401)
            data = response.get_json()
            self.assertEqual(data["attempts_remaining"], 4 - i)

        # Attempt 6 should return 423 locked
        response = self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        }, environ_overrides={"REMOTE_ADDR": "198.51.100.12"})
        self.assertEqual(response.status_code, 423)
        self.assertIn("locked", response.get_json()["error"])

    def test_mfa_setup_and_verify_flow(self):
        """Test full MFA registration and subsequent login verification flow."""
        # Authenticate doctor
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })

        # GET MFA Setup secret
        setup_res = self.client.get('/auth/mfa-setup')
        self.assertEqual(setup_res.status_code, 200)
        setup_data = setup_res.get_json()
        secret = setup_data["secret"]

        # Generate valid TOTP token code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Confirm and activate MFA
        confirm_res = self.client.post('/auth/mfa-setup', json={"code": code})
        self.assertEqual(confirm_res.status_code, 200)

        # Log out
        self.client.post('/auth/logout')

        # Login Step 1: should now demand MFA
        login_res = self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(login_res.get_json().get("mfa_required"))

        # Login Step 2: verify TOTP token
        code = totp.now()
        verify_res = self.client.post('/auth/mfa-verify', json={"code": code})
        self.assertEqual(verify_res.status_code, 200)
        self.assertIn("verified", verify_res.get_json()["message"])

    def test_profile_returns_only_current_user_and_recent_devices(self):
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })

        response = self.client.get('/auth/profile')

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["username"], "doctor_test")
        self.assertEqual(data["role"], Role.DOCTOR)
        self.assertNotIn("password_hash", data)
        self.assertEqual(len(data["devices"]), 1)

    def test_change_password_requires_current_password(self):
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })

        response = self.client.post('/auth/change-password', json={
            "current_password": "DoctorPass123!",
            "new_password": "NewDoctorPass456!"
        })

        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.doctor.check_password("NewDoctorPass456!"))

    def test_mfa_can_be_disabled_with_password_and_code(self):
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })
        setup = self.client.get('/auth/mfa-setup').get_json()
        self.client.post('/auth/mfa-setup', json={"code": pyotp.TOTP(setup["secret"]).now()})

        response = self.client.post('/auth/mfa-disable', json={
            "password": "DoctorPass123!",
            "code": pyotp.TOTP(setup["secret"]).now()
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.doctor.mfa_enabled)
        self.assertIsNone(self.doctor.mfa_secret)

    def test_record_encryption_tier_aware(self):
        """Test encryption keys match the user's subscription tier requirements."""
        # Free user (AES-128-GCM)
        free_payload = encrypt_for_user("Patient diagnosis text", "free")
        self.assertEqual(free_payload["alg"], "AES-128-GCM")
        self.assertEqual(decrypt_for_user(free_payload), "Patient diagnosis text")

        # Pro user (AES-256-GCM)
        pro_payload = encrypt_for_user("Sensitive diagnosis text", "pro")
        self.assertEqual(pro_payload["alg"], "AES-256-GCM")
        self.assertEqual(decrypt_for_user(pro_payload), "Sensitive diagnosis text")

    def test_tamper_evident_audit_chain(self):
        """Test that the hash-chained audit log successfully detects DB tampering."""
        # Perform some logged operations
        AuditLog.write(db.session, self.admin.id, "TEST_ACTION_1", "users", 1)
        AuditLog.write(db.session, self.doctor.id, "TEST_ACTION_2", "users", 2)

        # Verify chain is intact
        intact, broken_at = AuditLog.verify_chain(db.session)
        self.assertTrue(intact)
        self.assertIsNone(broken_at)

        # Simulate database tampering (modify entry #1 timestamp or hash)
        first_log = db.session.query(AuditLog).order_by(AuditLog.id.asc()).first()
        first_log.timestamp = "2020-01-01T00:00:00"
        db.session.commit()

        # Verify chain detects tampering
        intact, broken_at = AuditLog.verify_chain(db.session)
        self.assertFalse(intact)
        self.assertEqual(broken_at, first_log.id)

    def test_break_glass_emergency_access(self):
        """Test the emergency break-glass override flow & mandatory audit logging."""
        # Create a patient and record
        patient = Patient(full_name="John Doe", date_of_birth=datetime.now().date())
        db.session.add(patient)
        db.session.commit()

        rec = MedicalRecord(
            patient_id=patient.id,
            created_by=self.doctor.id,
            encryption_tier="free"
        )
        rec.diagnosis_payload = encrypt_for_user("Heart condition", "free")
        db.session.add(rec)
        db.session.commit()

        # Log in doctor
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })

        # Post break-glass override
        res = self.client.post(f'/records/{rec.id}/break-glass', json={
            "reason": "Attending doctor unavailable, vital signs dropping!"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("warning", data)
        self.assertEqual(data["record"]["diagnosis"], "Heart condition")

        # Verify audit log recorded the break-glass event
        last_log = db.session.query(AuditLog).order_by(AuditLog.id.desc()).first()
        self.assertEqual(last_log.action, "BREAK_GLASS_ACCESS")
        self.assertTrue(last_log.is_break_glass)
        self.assertIn("vital signs dropping", last_log.extra)

    def test_admin_user_management_crud(self):
        """Test admin user creation, update, and deletion via the management API."""
        self.client.post('/auth/login', json={
            "username": "admin_test",
            "password": "AdminPass123!"
        })

        create = self.client.post('/admin/users', json={
            "username": "team_member",
            "email": "team_member@vaultward.local",
            "password": "TeamPass123!",
            "role": Role.NURSE,
            "department": "Cardiology",
            "tier": "pro",
        })
        self.assertEqual(create.status_code, 201)
        user_id = create.get_json()["user_id"]

        update = self.client.put(f'/admin/users/{user_id}', json={
            "department": "ICU",
            "role": Role.DOCTOR,
            "is_active": False,
            "mfa_enabled": True,
        })
        self.assertEqual(update.status_code, 200)

        listing = self.client.get('/admin/users')
        self.assertEqual(listing.status_code, 200)
        updated_user = next(item for item in listing.get_json() if item["id"] == user_id)
        self.assertEqual(updated_user["department"], "ICU")
        self.assertEqual(updated_user["role"], Role.DOCTOR)
        self.assertEqual(updated_user["tier"], "free")
        self.assertFalse(updated_user["is_active"])
        self.assertTrue(updated_user["mfa_enabled"])

        upgrade = self.client.post(f'/admin/users/{user_id}/tier', json={
            "tier": "enterprise",
            "billing_period": "monthly",
            "provider": "stripe",
            "payment_reference": "test_admin_upgrade",
        })
        self.assertEqual(upgrade.status_code, 200)
        self.assertEqual(self.client.get('/admin/users').get_json()[-1]["tier"], "enterprise")

        delete = self.client.delete(f'/admin/users/{user_id}')
        self.assertEqual(delete.status_code, 200)
        self.assertEqual(delete.get_json()["message"], "User deactivated.")
        self.assertFalse(db.session.get(User, user_id).is_active)

    def test_security_activity_feed_maps_alerts_and_marks_read(self):
        AuditLog.write(
            db.session, self.doctor.id, "BREAK_GLASS_ACCESS",
            ip_address="10.0.0.12", extra={"reason": "Emergency review"},
            is_break_glass=True,
        )
        AuditLog.write(db.session, self.doctor.id, "LOGIN_FAILED", ip_address="10.0.0.13")

        self.client.post('/auth/login', json={
            "username": "admin_test",
            "password": "AdminPass123!"
        })
        response = self.client.get('/admin/security-activity')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertGreaterEqual(data["unread_count"], 3)
        self.assertEqual(data["events"][0]["title"], "MFA setup recommended")
        break_glass = next(event for event in data["events"] if event["severity"] == "critical")
        self.assertIn("Emergency review", break_glass["message"])

        marked = self.client.post('/admin/security-activity/mark-read')
        self.assertEqual(marked.status_code, 200)
        refreshed = self.client.get('/admin/security-activity').get_json()
        self.assertEqual(refreshed["unread_count"], 1)

    def test_billing_history_tracks_upgrade_and_cancelled_period(self):
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })

        upgrade = self.client.post('/subscriptions/upgrade', json={
            "tier": "pro",
            "billing_period": "annual",
            "provider": "stripe",
            "payment_reference": "test_billing_upgrade",
        })
        self.assertEqual(upgrade.status_code, 200)

        history = self.client.get('/subscriptions/billing-history')
        self.assertEqual(history.status_code, 200)
        data = history.get_json()
        self.assertEqual(data["current"]["tier"], "pro")
        self.assertEqual(data["current"]["amount"], 149.99)
        self.assertEqual(data["current"]["payment_status"], "paid")
        self.assertTrue(data["next_renewal"])

        self.client.post('/subscriptions/cancel')
        cancelled = self.client.get('/subscriptions/billing-history').get_json()
        self.assertIsNone(cancelled["current"])
        self.assertEqual(len(cancelled["history"]), 1)

    def test_expired_subscription_is_revoked_on_authenticated_request(self):
        self.client.post('/auth/login', json={
            "username": "doctor_test",
            "password": "DoctorPass123!"
        })
        upgrade = self.client.post('/subscriptions/upgrade', json={
            "tier": "pro",
            "billing_period": "monthly",
            "provider": "stripe",
            "payment_reference": "test_expired_subscription",
        })
        self.assertEqual(upgrade.status_code, 200)

        subscription = Subscription.query.filter_by(
            user_id=self.doctor.id, active=True
        ).one()
        subscription.expires_at = datetime.utcnow() - timedelta(days=1)
        db.session.commit()

        g.pop("_login_user", None)
        profile = self.client.get('/auth/profile')
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.get_json()["tier"], "free")
        db.session.refresh(subscription)
        self.assertFalse(subscription.active)


if __name__ == '__main__':
    unittest.main()
