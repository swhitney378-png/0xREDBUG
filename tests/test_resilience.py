import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch
from sqlalchemy.pool import NullPool

os.environ["VAULTWARD_MASTER_SECRET"] = "0123456789abcdef0123456789abcdef"
os.environ["SECRET_KEY"] = "test-secret"

from app import create_app
from app.config import Config
from app.crypto.engine import decrypt_for_user, encrypt_for_user
from app.crypto.rotation import encrypt_for_tier, rotate_tier_keys
from app.extensions import db
from app.models.key_version import KeyVersion
from app.models.patient import MedicalRecord, Patient
from app.models.user import Role, User
from app.services.backup import create_encrypted_backup, restore_encrypted_backup


class ResilienceTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "vaultward.sqlite"

        class TestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{database_path}"
            WTF_CSRF_ENABLED = False
            ENABLE_MAINTENANCE_SCHEDULER = False
            BACKUP_DIR = self.temp_dir.name
            SQLALCHEMY_ENGINE_OPTIONS = {"poolclass": NullPool}

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()

        self.admin = User(
            username="resilience_admin",
            email="resilience-admin@vaultward.local",
            role=Role.ADMIN,
            tier="enterprise",
        )
        self.admin.set_password("AdminPass123!")
        db.session.add(self.admin)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()
        self.temp_dir.cleanup()

    def _create_record(self):
        patient = Patient(full_name="Resilience Test", date_of_birth=date(1985, 5, 5))
        db.session.add(patient)
        db.session.commit()
        record = MedicalRecord(
            patient_id=patient.id,
            created_by=self.admin.id,
            record_type="consultation",
            encryption_tier="pro",
        )
        record.diagnosis_payload = encrypt_for_user("Rotating diagnosis", "pro", db.session)
        record.notes_payload = encrypt_for_user("Rotating notes", "pro", db.session)
        record.prescription_payload = encrypt_for_user("Rotating prescription", "pro", db.session)
        db.session.add(record)
        db.session.commit()
        return patient, record

    def test_encrypted_backup_restore_and_health(self):
        self._create_record()
        backup = create_encrypted_backup(db.engine, self.temp_dir.name)
        self.assertTrue(backup.suffix == ".vwb")

        db.session.query(Patient).delete()
        db.session.commit()
        self.assertEqual(Patient.query.count(), 0)

        restored = restore_encrypted_backup(db.engine, backup)
        self.assertTrue(restored["restored"])
        db.session.expire_all()
        self.assertEqual(Patient.query.count(), 1)

        health = self.client.get("/healthz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()["status"], "ok")

    def test_backup_inventory_reports_latest_manual_backup(self):
        self.client.post("/auth/login", json={
            "username": "resilience_admin",
            "password": "AdminPass123!",
        })

        create_response = self.client.post("/admin/maintenance/backup")
        self.assertEqual(create_response.status_code, 201)
        filename = create_response.get_json()["filename"]

        inventory = self.client.get("/admin/maintenance/backups")
        self.assertEqual(inventory.status_code, 200)
        payload = inventory.get_json()
        self.assertEqual(payload["last_backup"]["filename"], filename)
        self.assertEqual(payload["backups"][0]["filename"], filename)

    def test_key_rotation_reencrypts_records_and_preserves_readability(self):
        _, record = self._create_record()
        old_payload = record.diagnosis_payload
        old_notes_payload = record.notes_payload
        old_prescription_payload = record.prescription_payload
        old_version = old_payload["key_version"]

        result = rotate_tier_keys(db.session, "pro")
        self.assertTrue(result["rotated"])
        self.assertEqual(result["records_reencrypted"], 1)

        db.session.refresh(record)
        new_payload = record.diagnosis_payload
        self.assertGreater(new_payload["key_version"], old_version)
        self.assertNotEqual(new_payload["key_version"], old_version)
        self.assertEqual(decrypt_for_user(new_payload, db.session), "Rotating diagnosis")
        self.assertEqual(decrypt_for_user(record.notes_payload, db.session), "Rotating notes")
        self.assertEqual(decrypt_for_user(record.prescription_payload, db.session), "Rotating prescription")
        self.assertEqual(decrypt_for_user(old_payload, db.session), "Rotating diagnosis")
        self.assertEqual(decrypt_for_user(old_notes_payload, db.session), "Rotating notes")
        self.assertEqual(decrypt_for_user(old_prescription_payload, db.session), "Rotating prescription")

    def test_key_rotation_preserves_active_key_when_reencryption_fails(self):
        _, record = self._create_record()
        original_payload = record.diagnosis_payload
        active_key = KeyVersion.query.filter_by(tier="pro", active=True).one()
        active_version = active_key.version
        encrypt_calls = 0

        def fail_on_second_encryption(plaintext, tier, session):
            nonlocal encrypt_calls
            encrypt_calls += 1
            if encrypt_calls == 2:
                raise RuntimeError("failed")
            return encrypt_for_tier(plaintext, tier, session)

        with patch(
            "app.crypto.rotation.encrypt_for_tier",
            side_effect=fail_on_second_encryption,
        ):
            with self.assertRaises(RuntimeError):
                rotate_tier_keys(db.session, "pro")

        active_keys = KeyVersion.query.filter_by(tier="pro", active=True).all()
        self.assertEqual(len(active_keys), 1)
        self.assertEqual(active_keys[0].version, active_version)
        db.session.refresh(record)
        self.assertEqual(record.diagnosis_payload, original_payload)


if __name__ == "__main__":
    unittest.main()
