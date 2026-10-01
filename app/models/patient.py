import json
import uuid
from datetime import datetime, timezone
from ..extensions import db

def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_patient_code() -> str:
    return f"PT-{uuid.uuid4().hex[:10].upper()}"


class Patient(db.Model):
    __tablename__ = "patients"

    id                 = db.Column(db.Integer, primary_key=True)
    patient_code       = db.Column(db.String(32), unique=True, nullable=False, default=generate_patient_code)
    full_name          = db.Column(db.String(200), nullable=False)
    date_of_birth      = db.Column(db.Date, nullable=False)
    national_id        = db.Column(db.String(50), unique=True, nullable=True)
    gender             = db.Column(db.String(10))
    phone              = db.Column(db.String(30))
    email              = db.Column(db.String(120), nullable=True)
    address            = db.Column(db.Text)
    next_of_kin        = db.Column(db.String(200), nullable=True)
    blood_type         = db.Column(db.String(5), nullable=True)
    known_allergies    = db.Column(db.Text, nullable=True)
    chronic_conditions = db.Column(db.Text, nullable=True)
    current_medications= db.Column(db.Text, nullable=True)
    primary_physician  = db.Column(db.String(150), nullable=True)
    admission_date     = db.Column(db.Date, nullable=True)
    department         = db.Column(db.String(100), nullable=True)
    insurance_provider = db.Column(db.String(120), nullable=True)
    medical_aid_number = db.Column(db.String(120), nullable=True)
    referring_facility = db.Column(db.String(150), nullable=True)
    created_by         = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    updated_at         = db.Column(db.DateTime, nullable=True)
    updated_by         = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at         = db.Column(db.DateTime, default=utc_now_naive)
    retention_hold     = db.Column(db.Boolean, default=False, nullable=False)

    records = db.relationship("MedicalRecord", back_populates="patient", lazy="select")

    def to_dict(self):
        return {
            "id":                 self.id,
            "patient_id":         self.patient_code,
            "full_name":          self.full_name,
            "date_of_birth":      self.date_of_birth.isoformat(),
            "national_id":        self.national_id,
            "gender":             self.gender,
            "phone":              self.phone,
            "email":              self.email,
            "address":            self.address,
            "next_of_kin":        self.next_of_kin,
            "blood_type":         self.blood_type,
            "known_allergies":    self.known_allergies,
            "chronic_conditions": self.chronic_conditions,
            "current_medications": self.current_medications,
            "primary_physician":  self.primary_physician,
            "admission_date":     self.admission_date.isoformat() if self.admission_date else None,
            "department":         self.department,
            "insurance_provider": self.insurance_provider,
            "medical_aid_number": self.medical_aid_number,
            "referring_facility": self.referring_facility,
            "created_by":         self.created_by,
            "created_at":         self.created_at.isoformat() if self.created_at else None,
            "updated_by":         self.updated_by,
            "updated_at":         self.updated_at.isoformat() if self.updated_at else None,
            "retention_hold":     self.retention_hold,
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

    id           = db.Column(db.Integer, primary_key=True)
    patient_id   = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    created_by   = db.Column(db.Integer, db.ForeignKey("users.id"),    nullable=False)

    record_type  = db.Column(db.String(50))   # e.g. "consultation", "lab", "admission"

    # Encrypted fields (stored as JSON text)
    _diagnosis    = db.Column("diagnosis",    db.Text, nullable=False)
    _notes        = db.Column("notes",        db.Text, nullable=True)
    _prescription = db.Column("prescription", db.Text, nullable=True)

    encryption_tier  = db.Column(db.String(20), nullable=False)
    key_version      = db.Column(db.Integer, nullable=True)

    created_at   = db.Column(db.DateTime, default=utc_now_naive)
    updated_at   = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)

    patient          = db.relationship("Patient", back_populates="records")
    created_by_user  = db.relationship("User",    back_populates="records")

    # ─── property helpers ─────────────────────────────────────────────────────
    @property
    def diagnosis_payload(self) -> dict:
        return json.loads(self._diagnosis)

    @diagnosis_payload.setter
    def diagnosis_payload(self, val: dict):
        self._diagnosis = json.dumps(val)

    @property
    def notes_payload(self) -> "dict | None":
        return json.loads(self._notes) if self._notes else None

    @notes_payload.setter
    def notes_payload(self, val: "dict | None"):
        self._notes = json.dumps(val) if val else None

    @property
    def prescription_payload(self) -> "dict | None":
        return json.loads(self._prescription) if self._prescription else None

    @prescription_payload.setter
    def prescription_payload(self, val: "dict | None"):
        self._prescription = json.dumps(val) if val else None

    def __repr__(self):
        return f"<MedicalRecord {self.id} patient={self.patient_id}>"
