"""Privacy rights, retention controls, and data export routes."""
from datetime import datetime, timedelta, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user, login_required
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from ..extensions import db
from ..models.audit import AuditLog
from ..models.patient import MedicalRecord, Patient
from ..models.privacy import ErasureRequest, PatientConsent, SecurityIncident
from ..models.user import Role
from ..utils.decorators import admin_only, require_role
from ..crypto.engine import decrypt_for_user

privacy_bp = Blueprint("privacy", __name__, url_prefix="/privacy")


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _consent_dict(consent: PatientConsent) -> dict:
    return {
        "id": consent.id,
        "patient_id": consent.patient_id,
        "patient_code": consent.patient.patient_code,
        "patient_name": consent.patient.full_name,
        "purpose": consent.purpose,
        "notes": consent.notes,
        "status": consent.status,
        "authorized_by": consent.authorizer.username,
        "granted_at": consent.granted_at.isoformat(),
        "expires_at": consent.expires_at.isoformat() if consent.expires_at else None,
        "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
        "revoked_by": consent.revoker.username if consent.revoker else None,
        "revoke_reason": consent.revoke_reason,
    }


@privacy_bp.get("/consents")
@login_required
@require_role(*Role.ALL)
def list_consents():
    consents = PatientConsent.query.order_by(PatientConsent.granted_at.desc()).all()
    return jsonify([_consent_dict(consent) for consent in consents]), 200


@privacy_bp.post("/consents")
@login_required
@require_role(*Role.ALL)
def grant_consent():
    data = request.get_json(silent=True) or {}
    patient_id = data.get("patient_id")
    purpose = str(data.get("purpose", "")).strip()
    if not patient_id or not purpose:
        return jsonify({"error": "patient_id and purpose are required."}), 400
    if len(purpose) > 200:
        return jsonify({"error": "Purpose must be 200 characters or fewer."}), 400

    patient = db.get_or_404(Patient, int(patient_id))
    expires_at = None
    if data.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(data["expires_at"])
        except (TypeError, ValueError):
            return jsonify({"error": "expires_at must be an ISO date or datetime."}), 400
        if expires_at <= datetime.utcnow():
            return jsonify({"error": "Consent expiry must be in the future."}), 400

    consent = PatientConsent(
        patient_id=patient.id,
        authorized_by=current_user.id,
        purpose=purpose,
        notes=str(data.get("notes", "")).strip() or None,
        expires_at=expires_at,
    )
    db.session.add(consent)
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "PATIENT_CONSENT_GRANTED",
        table_affected="patient_consents", record_id=consent.id,
        ip_address=_ip(), extra={"patient_id": patient.id, "purpose": purpose},
    )
    return jsonify({"message": "Patient consent recorded.", "consent": _consent_dict(consent)}), 201


@privacy_bp.post("/consents/<int:consent_id>/revoke")
@login_required
@require_role(*Role.ALL)
def revoke_consent(consent_id):
    consent = db.get_or_404(PatientConsent, consent_id)
    if consent.status == "revoked":
        return jsonify({"error": "Consent is already revoked."}), 409
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "")).strip()
    if not reason:
        return jsonify({"error": "A reason is required to revoke consent."}), 400

    consent.status = "revoked"
    consent.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    consent.revoked_by = current_user.id
    consent.revoke_reason = reason[:255]
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "PATIENT_CONSENT_REVOKED",
        table_affected="patient_consents", record_id=consent.id,
        ip_address=_ip(), extra={"patient_id": consent.patient_id, "reason": reason},
    )
    return jsonify({"message": "Patient consent revoked.", "consent": _consent_dict(consent)}), 200


def _export_patient(patient: Patient) -> dict:
    records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.asc()).all()
    return {
        "patient": patient.to_dict(),
        "medical_records": [
            {
                "id": record.id,
                "record_type": record.record_type,
                "diagnosis": decrypt_for_user(record.diagnosis_payload, db.session),
                "notes": decrypt_for_user(record.notes_payload, db.session) if record.notes_payload else None,
                "prescription": decrypt_for_user(record.prescription_payload, db.session) if record.prescription_payload else None,
                "encryption_tier": record.encryption_tier,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "updated_at": record.updated_at.isoformat() if record.updated_at else None,
            }
            for record in records
        ],
    }


def _build_patient_export_pdf(patients: list[Patient], generated_at: str) -> BytesIO:
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="VaultWard Patient Data Export",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ExportTitle", parent=styles["Title"], alignment=TA_CENTER,
        textColor=colors.HexColor("#123d38"), spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Field", parent=styles["BodyText"], spaceAfter=4,
        wordWrap="CJK",
    ))
    story = [
        Paragraph("VaultWard Patient Data Export", styles["ExportTitle"]),
        Paragraph(f"Generated: {escape(generated_at)}", styles["BodyText"]),
        Paragraph(f"Patient count: {len(patients)}", styles["BodyText"]),
        Spacer(1, 14),
    ]

    for patient in patients:
        data = _export_patient(patient)
        details = data["patient"]
        story.append(Paragraph(
            f"{escape(details['full_name'])} ({escape(details['patient_id'])})",
            styles["Heading2"],
        ))
        for label, value in details.items():
            if label in {"full_name", "patient_id"}:
                continue
            display_value = "Not provided" if value is None else str(value)
            story.append(Paragraph(
                f"<b>{escape(label.replace('_', ' ').title())}:</b> "
                f"{escape(display_value).replace(chr(10), '<br/>')}",
                styles["Field"],
            ))

        if data["medical_records"]:
            story.append(Paragraph("Medical records", styles["Heading3"]))
            for record in data["medical_records"]:
                story.append(Paragraph(
                    f"<b>Record {record['id']} | {escape(record['record_type'] or 'Record')}"
                    f" | {escape(record['created_at'] or 'Date unavailable')}</b>",
                    styles["Field"],
                ))
                for field in ("diagnosis", "notes", "prescription", "encryption_tier", "updated_at"):
                    value = record[field]
                    if value is not None:
                        story.append(Paragraph(
                            f"<b>{field.replace('_', ' ').title()}:</b> "
                            f"{escape(str(value)).replace(chr(10), '<br/>')}",
                            styles["Field"],
                        ))
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("No medical records.", styles["Field"]))

        story.append(Spacer(1, 12))

    document.build(story)
    output.seek(0)
    return output


@privacy_bp.get("/export/patients/<int:patient_id>")
@login_required
@require_role(*Role.ALL)
def export_patient(patient_id):
    patient = db.get_or_404(Patient, patient_id)
    pdf = _build_patient_export_pdf([patient], datetime.utcnow().isoformat())
    AuditLog.write(
        db.session, current_user.id, "DATA_EXPORT",
        table_affected="patients", record_id=patient_id, ip_address=_ip(),
        extra={"export_type": "patient_record"},
    )
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vaultward-{patient.patient_code}-export.pdf",
    )


@privacy_bp.post("/erasure-requests")
@login_required
@require_role(*Role.ALL)
def request_erasure():
    data = request.get_json(silent=True) or {}
    patient_id = data.get("patient_id")
    reason = str(data.get("reason", "")).strip()
    if not patient_id or not reason:
        return jsonify({"error": "patient_id and reason are required."}), 400

    patient = db.get_or_404(Patient, int(patient_id))
    existing = ErasureRequest.query.filter_by(patient_id=patient.id, status="pending").first()
    if existing:
        return jsonify({"error": "A pending erasure request already exists.", "request_id": existing.id}), 409

    erasure_request = ErasureRequest(
        patient_id=patient.id,
        requester_id=current_user.id,
        reason=reason,
    )
    db.session.add(erasure_request)
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "ERASURE_REQUESTED",
        table_affected="patients", record_id=patient.id, ip_address=_ip(),
    )
    return jsonify({"message": "Erasure request submitted for admin review.", "request_id": erasure_request.id}), 201


@privacy_bp.get("/erasure-requests/<int:request_id>")
@login_required
@require_role(*Role.ALL)
def get_erasure_request(request_id):
    erasure_request = db.get_or_404(ErasureRequest, request_id)
    return jsonify({
        "id": erasure_request.id,
        "patient_id": erasure_request.patient_id,
        "status": erasure_request.status,
        "reason": erasure_request.reason,
        "decision_note": erasure_request.decision_note,
        "created_at": erasure_request.created_at.isoformat(),
        "reviewed_at": erasure_request.reviewed_at.isoformat() if erasure_request.reviewed_at else None,
    }), 200


def _delete_patient_data(patient: Patient) -> int:
    records = list(patient.records)
    for record in records:
        db.session.delete(record)
    db.session.delete(patient)
    return len(records)


@privacy_bp.get("/retention-policy")
@login_required
def retention_policy():
    years = current_app.config["RECORD_RETENTION_YEARS"]
    return jsonify({
        "retention_years": years,
        "retention_basis": "Records are retained for the configured healthcare retention period unless a longer legal, regulatory, contractual, or legal-hold requirement applies.",
        "legal_hold": "Records under legal hold are excluded from automated deletion until the hold is removed by an administrator.",
        "erasure": "Erasure requests are reviewed by an administrator and may be refused where retention is legally required.",
    }), 200


@privacy_bp.get("/data-export")
@login_required
@admin_only
def export_all_patients():
    patients = Patient.query.order_by(Patient.id.asc()).all()
    generated_at = datetime.utcnow().isoformat()
    pdf = _build_patient_export_pdf(patients, generated_at)
    AuditLog.write(
        db.session, current_user.id, "DATA_EXPORT_ALL",
        table_affected="patients", ip_address=_ip(),
        extra={"patient_count": len(patients)},
    )
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="vaultward-regulatory-export.pdf",
    )


@privacy_bp.get("/admin/retention/preview")
@login_required
@admin_only
def retention_preview():
    cutoff = datetime.utcnow() - timedelta(days=365 * current_app.config["RECORD_RETENTION_YEARS"])
    patients = Patient.query.filter(Patient.created_at < cutoff, Patient.retention_hold.is_(False)).all()
    return jsonify({
        "retention_years": current_app.config["RECORD_RETENTION_YEARS"],
        "cutoff": cutoff.isoformat(),
        "eligible_patients": len(patients),
        "eligible_patient_ids": [patient.id for patient in patients],
        "legal_hold_excluded": Patient.query.filter(Patient.created_at < cutoff, Patient.retention_hold.is_(True)).count(),
    }), 200


@privacy_bp.post("/admin/retention/purge")
@login_required
@admin_only
def purge_retained_data():
    cutoff = datetime.utcnow() - timedelta(days=365 * current_app.config["RECORD_RETENTION_YEARS"])
    patients = Patient.query.filter(Patient.created_at < cutoff, Patient.retention_hold.is_(False)).all()
    deleted_records = sum(_delete_patient_data(patient) for patient in patients)
    deleted_patients = len(patients)
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "RETENTION_PURGE",
        table_affected="patients", ip_address=_ip(),
        extra={"cutoff": cutoff.isoformat(), "deleted_patients": deleted_patients, "deleted_records": deleted_records},
    )
    return jsonify({"message": "Retention purge completed.", "deleted_patients": deleted_patients, "deleted_records": deleted_records}), 200


@privacy_bp.put("/admin/patients/<int:patient_id>/legal-hold")
@login_required
@admin_only
def set_legal_hold(patient_id):
    patient = db.get_or_404(Patient, patient_id)
    data = request.get_json(silent=True) or {}
    if "retention_hold" not in data or not isinstance(data["retention_hold"], bool):
        return jsonify({"error": "retention_hold must be a boolean."}), 400
    patient.retention_hold = data["retention_hold"]
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "LEGAL_HOLD_UPDATED",
        table_affected="patients", record_id=patient_id, ip_address=_ip(),
        extra={"retention_hold": patient.retention_hold},
    )
    return jsonify({"patient_id": patient_id, "retention_hold": patient.retention_hold}), 200


@privacy_bp.get("/admin/incidents")
@login_required
@admin_only
def list_incidents():
    incidents = SecurityIncident.query.order_by(SecurityIncident.discovered_at.desc()).all()
    return jsonify([_incident_dict(incident) for incident in incidents]), 200


def _incident_dict(incident: SecurityIncident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
        "discovered_at": incident.discovered_at.isoformat(),
        "containment_at": incident.containment_at.isoformat() if incident.containment_at else None,
        "regulator_notified_at": incident.regulator_notified_at.isoformat() if incident.regulator_notified_at else None,
        "affected_people_notified_at": incident.affected_people_notified_at.isoformat() if incident.affected_people_notified_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "owner_id": incident.owner_id,
    }


@privacy_bp.post("/admin/incidents")
@login_required
@admin_only
def create_incident():
    data = request.get_json(silent=True) or {}
    if not data.get("title") or not data.get("summary"):
        return jsonify({"error": "title and summary are required."}), 400
    if data.get("severity", "medium") not in {"low", "medium", "high", "critical"}:
        return jsonify({"error": "severity must be low, medium, high, or critical."}), 400
    incident = SecurityIncident(
        title=str(data["title"]).strip(),
        summary=str(data["summary"]).strip(),
        severity=data.get("severity", "medium"),
        owner_id=current_user.id,
    )
    db.session.add(incident)
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "SECURITY_INCIDENT_OPENED",
        table_affected="security_incidents", record_id=incident.id, ip_address=_ip(),
        extra={"severity": incident.severity},
    )
    return jsonify(_incident_dict(incident)), 201


@privacy_bp.put("/admin/incidents/<int:incident_id>")
@login_required
@admin_only
def update_incident(incident_id):
    incident = db.get_or_404(SecurityIncident, incident_id)
    data = request.get_json(silent=True) or {}
    allowed_statuses = {"open", "contained", "notified", "resolved"}
    if "status" in data and data["status"] not in allowed_statuses:
        return jsonify({"error": "status must be open, contained, notified, or resolved."}), 400
    incident.status = data.get("status", incident.status)
    now = datetime.utcnow()
    if incident.status in {"contained", "notified", "resolved"} and not incident.containment_at:
        incident.containment_at = now
    if incident.status in {"notified", "resolved"} and not incident.regulator_notified_at:
        incident.regulator_notified_at = now
        incident.affected_people_notified_at = now
    if incident.status == "resolved" and not incident.resolved_at:
        incident.resolved_at = now
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id, "SECURITY_INCIDENT_UPDATED",
        table_affected="security_incidents", record_id=incident.id, ip_address=_ip(),
        extra={"status": incident.status},
    )
    return jsonify(_incident_dict(incident)), 200


@privacy_bp.get("/admin/erasure-requests")
@login_required
@admin_only
def list_erasure_requests():
    requests = ErasureRequest.query.order_by(ErasureRequest.created_at.desc()).all()
    return jsonify([
        {
            "id": item.id,
            "patient_id": item.patient_id,
            "status": item.status,
            "reason": item.reason,
            "created_at": item.created_at.isoformat(),
            "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else None,
        }
        for item in requests
    ]), 200


@privacy_bp.post("/admin/erasure-requests/<int:request_id>/decision")
@login_required
@admin_only
def decide_erasure_request(request_id):
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision", "")).lower()
    note = str(data.get("note", "")).strip()
    if decision not in {"approve", "reject"} or not note:
        return jsonify({"error": "decision must be approve or reject, and note is required."}), 400

    erasure_request = db.get_or_404(ErasureRequest, request_id)
    if erasure_request.status != "pending":
        return jsonify({"error": "This erasure request has already been decided."}), 409

    patient = db.get_or_404(Patient, erasure_request.patient_id)
    if decision == "approve" and patient.retention_hold:
        return jsonify({"error": "Cannot erase a patient record while a legal hold is active."}), 409

    erasure_request.status = "approved" if decision == "approve" else "rejected"
    erasure_request.decision_note = note
    erasure_request.reviewed_by = current_user.id
    erasure_request.reviewed_at = datetime.utcnow()
    deleted_records = _delete_patient_data(patient) if decision == "approve" else 0
    db.session.commit()
    AuditLog.write(
        db.session, current_user.id,
        "ERASURE_APPROVED" if decision == "approve" else "ERASURE_REJECTED",
        table_affected="patients", record_id=erasure_request.patient_id, ip_address=_ip(),
        extra={"request_id": request_id, "deleted_records": deleted_records, "note": note},
    )
    return jsonify({"message": f"Erasure request {erasure_request.status}.", "deleted_records": deleted_records}), 200
