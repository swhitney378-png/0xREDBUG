from datetime import datetime, timezone
from ..extensions import db


def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ErasureRequest(db.Model):
    __tablename__ = "erasure_requests"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id", ondelete="SET NULL"), nullable=True)
    requester_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    decision_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    patient = db.relationship("Patient", backref=db.backref("erasure_requests", lazy="select"))
    requester = db.relationship("User", foreign_keys=[requester_id])
    reviewer = db.relationship("User", foreign_keys=[reviewed_by])


class SecurityIncident(db.Model):
    __tablename__ = "security_incidents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="medium")
    status = db.Column(db.String(20), nullable=False, default="open")
    discovered_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    containment_at = db.Column(db.DateTime, nullable=True)
    regulator_notified_at = db.Column(db.DateTime, nullable=True)
    affected_people_notified_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)

    owner = db.relationship("User", foreign_keys=[owner_id])


class PatientConsent(db.Model):
    __tablename__ = "patient_consents"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id", ondelete="CASCADE"), nullable=False)
    authorized_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="active")
    granted_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    revoke_reason = db.Column(db.String(255), nullable=True)

    patient = db.relationship("Patient", backref=db.backref("consents", lazy="select"))
    authorizer = db.relationship("User", foreign_keys=[authorized_by])
    revoker = db.relationship("User", foreign_keys=[revoked_by])
