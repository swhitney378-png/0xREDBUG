# VaultWard Data Governance Policy

This policy is an implementation baseline, not legal advice. The hospital or data controller must confirm the retention period, lawful basis, patient notice, and regulator deadlines for each jurisdiction and contract.

## Retention

- VaultWard retains patient profiles and medical records for **7 years by default**, configured by `RECORD_RETENTION_YEARS`.
- A controller may set a longer period where healthcare, regulatory, contractual, insurance, litigation, or archival requirements apply.
- Retention is measured from the patient record creation date in the current implementation. A production policy should align the start event with the applicable law or last clinical activity.
- Administrators review candidates with `GET /privacy/admin/retention/preview` before deletion.
- Administrators execute deletion with `POST /privacy/admin/retention/purge`. The purge excludes records under legal hold and writes a hash-chained audit event.
- Legal holds are managed with `PUT /privacy/admin/patients/<id>/legal-hold`. A legal hold suspends automated retention deletion.

## Right to Erasure

1. An authorized user submits `POST /privacy/erasure-requests` with the patient ID and a reason.
2. An administrator reviews requests using `GET /privacy/admin/erasure-requests`.
3. The administrator approves or rejects with `POST /privacy/admin/erasure-requests/<id>/decision` and a written decision note.
4. Approved deletion is blocked while a legal hold is active.
5. Approved deletion removes the patient profile and medical records while retaining the erasure request decision as accountability evidence. The patient reference is set to null after deletion.
6. A request may be rejected where retention is required by law, a legal hold, a public-interest obligation, or another documented controller duty.

Deletion is irreversible. Before approval, the controller should confirm identity, scope, backups, downstream processors, and any statutory retention exception.

## Data Export

- An authorized staff member can export one patient record with `GET /privacy/export/patients/<id>`.
- An administrator can export all patient records for a regulator or lawful data request with `GET /privacy/data-export`.
- Exports contain decrypted clinical data, are returned as JSON attachments, and create audit events without recording clinical contents in the audit log.
- Exports must be transferred through an approved secure channel, access-controlled, time-limited, and deleted from temporary locations after delivery.

## Access and Accountability

All export, erasure, retention, legal-hold, and incident actions are authenticated and audit logged. The hash chain should be verified regularly with `GET /admin/audit/verify-chain`.
