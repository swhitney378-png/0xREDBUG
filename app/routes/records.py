"""
Medical records CRUD — all sensitive fields are encrypted/decrypted
via the tier-aware crypto engine.

Routes:
  GET    /records/patients           — list patients
  POST   /records/patients           — create patient
  GET    /records/patients/<id>      — get patient + records
  POST   /records/patients/<id>/records — add medical record (encrypted)
  GET    /records/<id>               — get single record (decrypted on the fly)
  PUT    /records/<id>               — update record
  DELETE /records/<id>               — soft-delete (admin only)
  POST   /records/<id>/break-glass   — emergency access override
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from ..extensions import db
from ..models.patient import Patient, MedicalRecord
from ..models.audit import AuditLog
from ..models.user import Role
from ..utils.decorators import require_role
from ..crypto.engine import encrypt_for_user, decrypt_for_user
from ..extensions import limiter

records_bp = Blueprint("records", __name__, url_prefix="/records")


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _decrypt_record(rec: MedicalRecord) -> dict:
    """Return a plain-text dict for a single record."""
    return {
        "id":               rec.id,
        "patient_id":       rec.patient_id,
        "record_type":      rec.record_type,
        "diagnosis":        decrypt_for_user(rec.diagnosis_payload, db.session),
        "notes":            decrypt_for_user(rec.notes_payload, db.session)        if rec.notes_payload        else None,
        "prescription":     decrypt_for_user(rec.prescription_payload, db.session) if rec.prescription_payload else None,
        "encryption_tier":  rec.encryption_tier,
        "created_at":       rec.created_at.isoformat(),
        "updated_at":       rec.updated_at.isoformat(),
    }


# ─── Patients ─────────────────────────────────────────────────────────────────

@records_bp.get("/patients")
@login_required
@require_role(*Role.ALL)
def list_patients():
    q          = request.args.get("q", "").strip()
    page       = int(request.args.get("page", 1))
    query      = Patient.query
    if q:
        query  = query.filter(Patient.full_name.ilike(f"%{q}%"))
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    return jsonify(
        {
            "patients": [p.to_dict() for p in pagination.items],
            "total":    pagination.total,
            "page":     page,
            "pages":    pagination.pages,
        }
    ), 200


@records_bp.post("/patients")
@login_required
@require_role(Role.ADMIN, Role.RECORDS_OFFICER, Role.DOCTOR)
def create_patient():
    data     = request.get_json(silent=True) or {}
    required = ["full_name", "date_of_birth"]
    if not all(data.get(f) for f in required):
        return jsonify({"error": "full_name and date_of_birth are required."}), 400

    from datetime import date
    try:
        dob = date.fromisoformat(data["date_of_birth"])
    except ValueError:
        return jsonify({"error": "date_of_birth must be YYYY-MM-DD."}), 400

    admission_date = None
    if data.get("admission_date"):
        try:
            admission_date = date.fromisoformat(data["admission_date"])
        except ValueError:
            return jsonify({"error": "admission_date must be YYYY-MM-DD."}), 400

    patient = Patient(
        full_name          = data["full_name"],
        date_of_birth      = dob,
        national_id        = data.get("national_id"),
        gender             = data.get("gender"),
        phone              = data.get("phone"),
        email              = data.get("email"),
        address            = data.get("address"),
        next_of_kin        = data.get("next_of_kin"),
        blood_type         = data.get("blood_type"),
        known_allergies    = data.get("known_allergies"),
        chronic_conditions = data.get("chronic_conditions"),
        current_medications= data.get("current_medications"),
        primary_physician  = data.get("primary_physician"),
        admission_date     = admission_date,
        department         = data.get("department"),
        insurance_provider = data.get("insurance_provider"),
        medical_aid_number = data.get("medical_aid_number"),
        referring_facility = data.get("referring_facility"),
        created_by         = current_user.id,
        updated_by         = current_user.id,
    )
    db.session.add(patient)
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "CREATE_PATIENT",
        table_affected="patients", record_id=patient.id, ip_address=_ip(),
    )
    return jsonify({"message": "Patient created.", "patient": patient.to_dict()}), 201


@records_bp.get("/patients/<int:patient_id>")
@login_required
@require_role(*Role.ALL)
def get_patient(patient_id):
    patient     = db.get_or_404(Patient, patient_id)
    records_raw = (
        MedicalRecord.query
        .filter_by(patient_id=patient_id)
        .order_by(MedicalRecord.created_at.desc())
        .all()
    )

    AuditLog.write(
        db.session, current_user.id, "VIEW_PATIENT",
        table_affected="patients", record_id=patient_id, ip_address=_ip(),
    )
    return jsonify(
        {
            "patient": patient.to_dict(),
            "records": [_decrypt_record(r) for r in records_raw],
        }
    ), 200


@records_bp.put("/patients/<int:patient_id>")
@login_required
@require_role(Role.ADMIN)
def update_patient(patient_id):
    patient = db.get_or_404(Patient, patient_id)
    data = request.get_json(silent=True) or {}

    if not data.get("full_name") or not data.get("date_of_birth"):
        return jsonify({"error": "full_name and date_of_birth are required."}), 400

    from datetime import date

    try:
        patient.date_of_birth = date.fromisoformat(data["date_of_birth"])
    except ValueError:
        return jsonify({"error": "date_of_birth must be YYYY-MM-DD."}), 400

    if data.get("admission_date"):
        try:
            patient.admission_date = date.fromisoformat(data["admission_date"])
        except ValueError:
            return jsonify({"error": "admission_date must be YYYY-MM-DD."}), 400
    else:
        patient.admission_date = None

    editable_fields = (
        "full_name", "national_id", "gender", "phone", "email", "address",
        "next_of_kin", "blood_type", "known_allergies", "chronic_conditions",
        "current_medications", "primary_physician", "department",
        "insurance_provider", "medical_aid_number", "referring_facility",
    )
    for field in editable_fields:
        if field in data:
            setattr(patient, field, data[field] or None)
    patient.full_name = data["full_name"].strip()
    patient.updated_by = current_user.id
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "UPDATE_PATIENT",
        table_affected="patients", record_id=patient_id, ip_address=_ip(),
    )
    return jsonify({"message": "Patient updated.", "patient": patient.to_dict()}), 200


@records_bp.delete("/patients/<int:patient_id>")
@login_required
@require_role(Role.ADMIN)
def delete_patient(patient_id):
    patient = db.get_or_404(Patient, patient_id)
    record_count = len(patient.records)
    for record in patient.records:
        db.session.delete(record)
    db.session.delete(patient)
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "DELETE_PATIENT",
        table_affected="patients", record_id=patient_id, ip_address=_ip(),
        extra={"medical_records_deleted": record_count},
    )
    return jsonify({"message": "Patient removed."}), 200


# ─── Medical Records ──────────────────────────────────────────────────────────

@records_bp.post("/patients/<int:patient_id>/records")
@login_required
@require_role(Role.ADMIN, Role.DOCTOR)
def add_record(patient_id):
    db.get_or_404(Patient, patient_id)
    data = request.get_json(silent=True) or {}

    if not data.get("diagnosis"):
        return jsonify({"error": "diagnosis is required."}), 400

    tier = current_user.tier
    rec  = MedicalRecord(
        patient_id      = patient_id,
        created_by      = current_user.id,
        record_type     = data.get("record_type", "consultation"),
        encryption_tier = tier,
    )
    rec.diagnosis_payload    = encrypt_for_user(data["diagnosis"],          tier, db.session)
    rec.notes_payload        = encrypt_for_user(data["notes"],        tier, db.session) if data.get("notes")        else None
    rec.prescription_payload = encrypt_for_user(data["prescription"], tier, db.session) if data.get("prescription") else None
    rec.key_version = rec.diagnosis_payload.get("key_version")

    db.session.add(rec)
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "CREATE_RECORD",
        table_affected="medical_records", record_id=rec.id, ip_address=_ip(),
        extra={"tier": tier, "patient_id": patient_id},
    )
    return jsonify({"message": "Record created.", "record_id": rec.id}), 201


@records_bp.get("/<int:record_id>")
@login_required
def get_record(record_id):
    rec = db.get_or_404(MedicalRecord, record_id)
    AuditLog.write(
        db.session, current_user.id, "VIEW_RECORD",
        table_affected="medical_records", record_id=record_id, ip_address=_ip(),
    )
    return jsonify(_decrypt_record(rec)), 200


@records_bp.put("/<int:record_id>")
@login_required
@require_role(Role.ADMIN, Role.DOCTOR)
def update_record(record_id):
    rec  = db.get_or_404(MedicalRecord, record_id)
    data = request.get_json(silent=True) or {}
    tier = current_user.tier

    if "diagnosis" in data:
        rec.diagnosis_payload = encrypt_for_user(data["diagnosis"], tier, db.session)
    if "notes" in data:
        rec.notes_payload = encrypt_for_user(data["notes"], tier, db.session) if data["notes"] else None
    if "prescription" in data:
        rec.prescription_payload = (
            encrypt_for_user(data["prescription"], tier, db.session) if data["prescription"] else None
        )

    rec.encryption_tier = tier
    rec.key_version = rec.diagnosis_payload.get("key_version") if rec.diagnosis_payload else None
    db.session.commit()

    AuditLog.write(
        db.session, current_user.id, "UPDATE_RECORD",
        table_affected="medical_records", record_id=record_id, ip_address=_ip(),
    )
    return jsonify({"message": "Record updated."}), 200


@records_bp.delete("/<int:record_id>")
@login_required
@require_role(Role.ADMIN)
def delete_record(record_id):
    rec = db.get_or_404(MedicalRecord, record_id)
    db.session.delete(rec)
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "DELETE_RECORD",
        table_affected="medical_records", record_id=record_id, ip_address=_ip(),
    )
    return jsonify({"message": "Record deleted."}), 200


# ─── Break-glass emergency access ────────────────────────────────────────────

@records_bp.post("/<int:record_id>/break-glass")
@login_required
@require_role(Role.DOCTOR, Role.ADMIN)
@limiter.limit("3 per minute")
def break_glass(record_id):
    """
    Emergency override — grants access to a record outside normal
    permission boundaries. Every single use is flagged in the audit log
    for mandatory security review. The doctor must supply a reason.
    """
    data   = request.get_json(silent=True) or {}
    reason = data.get("reason", "").strip()
    if not reason:
        return jsonify({"error": "A reason must be provided for break-glass access."}), 400

    rec = db.get_or_404(MedicalRecord, record_id)
    AuditLog.write(
        db.session, current_user.id, "BREAK_GLASS_ACCESS",
        table_affected="medical_records", record_id=record_id, ip_address=_ip(),
        is_break_glass=True, extra={"reason": reason},
    )

    return jsonify(
        {
            "warning": "Break-glass access granted. This access is logged and will be reviewed.",
            "record":  _decrypt_record(rec),
        }
    ), 200
