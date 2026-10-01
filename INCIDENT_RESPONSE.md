# VaultWard Security Incident Response Plan

This plan is the operational baseline for suspected or confirmed unauthorized access, disclosure, alteration, loss, ransomware, credential compromise, or service abuse involving VaultWard data.

## 1. Detect and record

- Any staff member who suspects an incident reports it immediately to the security/privacy owner and the hospital incident channel.
- An administrator opens a register entry with `POST /privacy/admin/incidents`, recording a neutral summary, severity, and owner.
- Preserve timestamps, affected systems, alerts, access logs, audit-log exports, and relevant evidence. Do not alter or delete suspected evidence.
- Record the incident ID and keep clinical content out of ticket titles and chat messages.

## 2. Triage and scope

- Classify severity as low, medium, high, or critical.
- Establish what happened, when it was discovered, which accounts/systems/data classes were involved, and whether confidentiality, integrity, or availability is affected.
- Determine whether patient data, credentials, encryption keys, backups, processors, or regulators may be affected.
- Verify the audit chain and preserve a read-only copy of relevant logs.

## 3. Contain

- Disable compromised accounts, revoke sessions/tokens, rotate exposed credentials and keys, and restrict network access as appropriate.
- Preserve evidence before destructive remediation where safe to do so.
- Update the incident status to `contained` with `PUT /privacy/admin/incidents/<id>`.
- Apply legal holds to affected patient records when deletion or alteration could obstruct investigation or legal obligations.

## 4. Assess notification duties

- The privacy owner and legal counsel determine whether notification is required under the applicable healthcare/privacy law, contract, or regulator rule.
- Identify the competent supervisory authority, required deadline, affected people, processors, and required content. Deadlines vary by jurisdiction and must not be guessed from this document.
- Prepare a factual notice covering the nature of the breach, categories of data and people affected, likely consequences, mitigation, contact point, and recommended protective actions.
- Notify the regulator and affected people through approved secure channels when required. Never include passwords, private keys, or unnecessary clinical details in the notice.
- Update the incident status to `notified` only after the responsible owner confirms the required notifications were sent and records the notification evidence outside the database.

## 5. Eradicate and recover

- Remove persistence, patch the cause, restore from known-good backups, rotate credentials/keys, and monitor for recurrence.
- Validate access controls, encryption, audit logging, backups, and application health before returning to normal operation.
- Keep affected services restricted until the owner signs off recovery.

## 6. Close and learn

- Record root cause, timeline, decisions, notifications, evidence location, costs, and corrective actions.
- Update the incident to `resolved` with `PUT /privacy/admin/incidents/<id>`.
- Conduct a post-incident review and track corrective actions to completion.
- Retain the incident record and evidence according to the applicable legal and governance retention requirements.

## Operational safeguards

- This plan does not replace legal advice or a jurisdiction-specific breach-notification matrix.
- Use least privilege, MFA, secure communications, and a second-person review for regulator and patient notifications.
- Do not use production patient data in test exports or incident exercises.
