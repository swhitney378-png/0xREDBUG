import json
from datetime import datetime
from ..extensions import db


class Patient(db.Model):
    __tablename__ = "patients"

    id           = db.Column(db.Integer, primary_key=True)
    full_name    = db.Column(db.String(200), nullable=False)
    date_of_birth= db.Column(db.Date, nullable=False)
    national_id  = db.Column(db.String(50), unique=True, nullable=True)
    gender       = db.Column(db.String(10))
    phone        = db.Column(db.String(30))
    address      = db.Column(db.Text)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    records      = db.relationship("MedicalRecord", back_populates="patient", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "date_of_birth": self.date_of_birth.isoformat(),
            "national_id": self.national_id,
            "gender": self.gender,
            "phone": self.phone,
        }

    def __repr__(self):
        return f"<Patient {self.full_name}>"


class MedicalRecord(db.Model):
    """
    Sensitive columns (diagnosis, notes, prescription) are stored as JSON
    payloads produced by the crypto engine — never as plain text.

    Schema of each encrypted column (stored as TEXT / JSON string):
        {
          "ciphertext": "<b64>",
          "nonce": "<b64>",
          "salt": "<b64>",
          "alg": "AES-128-GCM" | "AES-256-GCM",
          "tier_at_encryption": "free" | "pro" | "enterprise"
        }
    """
    __tablename__ = "medical_records"

    id                  = db.Column(db.Integer, primary_key=True)
    patient_id          = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    created_by          = db.Column(db.Integer, db.ForeignKey("users.id"),    nullable=False)

    record_type         = db.Column(db.String(50))          # e.g. "consultation", "lab", "admission"

    # Encrypted fields (stored as JSON text)
    _diagnosis          = db.Column("diagnosis",    db.Text, nullable=False)
    _notes              = db.Column("notes",        db.Text, nullable=True)
    _prescription       = db.Column("prescription", db.Text, nullable=True)

    encryption_tier     = db.Column(db.String(20), nullable=False)
    is_break_glass      = db.Column(db.Boolean, default=False)  # accessed under emergency override

    created_at          = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at          = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patient             = db.relationship("Patient",  back_populates="records")
    created_by_user     = db.relationship("User",     back_populates="records")

    # ─── property helpers ─────────────────────────────────────────────────────
    @property
    def diagnosis_payload(self) -> dict:
        return json.loads(self._diagnosis)

    @diagnosis_payload.setter
    def diagnosis_payload(self, val: dict):
        self._diagnosis = json.dumps(val)

    @property
    def notes_payload(self) -> dict | None:
        return json.loads(self._notes) if self._notes else None

    @notes_payload.setter
    def notes_payload(self, val: dict | None):
        self._notes = json.dumps(val) if val else None

    @property
    def prescription_payload(self) -> dict | None:
        return json.loads(self._prescription) if self._prescription else None

    @prescription_payload.setter
    def prescription_payload(self, val: dict | None):
        self._prescription = json.dumps(val) if val else None

    def __repr__(self):
        return f"<MedicalRecord {self.id} patient={self.patient_id}>"
