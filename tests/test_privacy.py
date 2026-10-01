import os
import unittest
from datetime import date

os.environ["VAULTWARD_MASTER_SECRET"] = "0123456789abcdef0123456789abcdef"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app import create_app
from app.config import Config
from app.crypto.engine import encrypt_for_user
from app.extensions import db
from app.models.audit import AuditLog
from app.models.patient import MedicalRecord, Patient
from app.models.user import Role, User


class PrivacyWorkflowTestCase(unittest.TestCase):
    def setUp(self):
        class TestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            WTF_CSRF_ENABLED = False
            RECORD_RETENTION_YEARS = 7

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()

        self.admin = User(
            username="privacy_admin",
            email="privacy-admin@vaultward.local",
            role=Role.ADMIN,
            tier="enterprise",
        )
        self.admin.set_password("AdminPass123!")
        db.session.add(self.admin)
        db.session.commit()

        self.patient = Patient(full_name="Privacy Test", date_of_birth=date(1980, 1, 1))
        db.session.add(self.patient)
        db.session.commit()
        record = MedicalRecord(
            patient_id=self.patient.id,
            created_by=self.admin.id,
            record_type="consultation",
            encryption_tier="enterprise",
        )
        record.diagnosis_payload = encrypt_for_user("Private diagnosis", "enterprise")
        db.session.add(record)
        db.session.commit()

        self.client.post("/auth/login", json={
            "username": "privacy_admin",
            "password": "AdminPass123!",
        })

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_policy_and_export_are_available_and_audited(self):
        policy = self.client.get("/privacy/retention-policy")
        self.assertEqual(policy.status_code, 200)
        self.assertEqual(policy.get_json()["retention_years"], 7)

        export = self.client.get(f"/privacy/export/patients/{self.patient.id}")
        self.assertEqual(export.status_code, 200)
        self.assertEqual(export.mimetype, "application/pdf")
        self.assertIn(
            f"vaultward-{self.patient.patient_code}-export.pdf",
            export.headers["Content-Disposition"],
        )
        self.assertTrue(export.data.startswith(b"%PDF-"))
        self.assertEqual(AuditLog.query.filter_by(action="DATA_EXPORT").count(), 1)

    def test_all_patient_export_downloads_pdf_and_is_audited(self):
        response = self.client.get("/privacy/data-export")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn("vaultward-regulatory-export.pdf", response.headers["Content-Disposition"])
        self.assertTrue(response.data.startswith(b"%PDF-"))
        self.assertEqual(AuditLog.query.filter_by(action="DATA_EXPORT_ALL").count(), 1)

    def test_admin_can_open_and_list_security_incident(self):
        created = self.client.post(
            "/privacy/admin/incidents",
            json={
                "title": "Compromise",
                "severity": "medium",
                "summary": "Investigating a reported account compromise.",
            },
        )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.get_json()["status"], "open")
        listed = self.client.get("/privacy/admin/incidents")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()[0]["title"], "Compromise")

    def test_legal_hold_blocks_erasure_decision(self):
        hold = self.client.put(
            f"/privacy/admin/patients/{self.patient.id}/legal-hold",
            json={"retention_hold": True},
        )
        self.assertEqual(hold.status_code, 200)

        request_response = self.client.post(
            "/privacy/erasure-requests",
            json={"patient_id": self.patient.id, "reason": "Verified erasure request."},
        )
        self.assertEqual(request_response.status_code, 201)
        request_id = request_response.get_json()["request_id"]

        decision = self.client.post(
            f"/privacy/admin/erasure-requests/{request_id}/decision",
            json={"decision": "approve", "note": "Legal hold remains active."},
        )
        self.assertEqual(decision.status_code, 409)
        self.assertIsNotNone(db.session.get(Patient, self.patient.id))

    def test_default_retention_policy_is_available(self):
        class DefaultPolicyConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            WTF_CSRF_ENABLED = False

        app = create_app(DefaultPolicyConfig)
        with app.app_context():
            db.create_all()
            admin = User(
                username="policy_admin",
                email="policy-admin@vaultward.local",
                role=Role.ADMIN,
            )
            admin.set_password("AdminPass123!")
            db.session.add(admin)
            db.session.commit()
            with app.test_client() as client:
                login = client.post("/auth/login", json={
                    "username": "policy_admin",
                    "password": "AdminPass123!",
                })
                self.assertEqual(login.status_code, 200)
                response = client.get("/privacy/retention-policy")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["retention_years"], 7)

    def test_patient_consent_can_be_granted_and_revoked(self):
        grant = self.client.post(
            "/privacy/consents",
            json={
                "patient_id": self.patient.id,
                "purpose": "Ongoing clinical treatment",
                "notes": "Patient authorized the care team.",
            },
        )
        self.assertEqual(grant.status_code, 201)
        consent_id = grant.get_json()["consent"]["id"]
        self.assertEqual(grant.get_json()["consent"]["authorized_by"], "privacy_admin")

        listed = self.client.get("/privacy/consents")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()[0]["status"], "active")

        revoke = self.client.post(
            f"/privacy/consents/{consent_id}/revoke",
            json={"reason": "Treatment episode completed."},
        )
        self.assertEqual(revoke.status_code, 200)
        self.assertEqual(revoke.get_json()["consent"]["status"], "revoked")
        self.assertEqual(
            AuditLog.query.filter_by(action="PATIENT_CONSENT_GRANTED").count(), 1
        )
        self.assertEqual(
            AuditLog.query.filter_by(action="PATIENT_CONSENT_REVOKED").count(), 1
        )


if __name__ == "__main__":
    unittest.main()
