# VaultWard API Reference

Base URL: `http://localhost:3452` (dev) | `https://your-hospital-domain.com` (prod)
All requests/responses are `application/json`.
Protected routes require a session cookie from a successful login.
State-changing browser requests must include the CSRF token from the page's
`csrf-token` meta tag in the `X-CSRFToken` header.

---

## Auth  `/auth`

| Method | Route           | Auth | Description                        |
|--------|-----------------|------|------------------------------------|
| POST   | /auth/login     | No   | Step 1: username + password        |
| POST   | /auth/mfa-verify| No   | Step 2: TOTP code (if MFA enabled) |
| POST   | /auth/logout    | Yes  | Clear session                      |
| GET    | /auth/mfa-setup | Yes  | Generate MFA QR secret             |
| POST   | /auth/mfa-setup | Yes  | Confirm code and activate MFA      |

### POST /auth/login
```json
{ "username": "w.madzorera", "password": "SecurePass123!" }
```
Response (no MFA):
```json
{ "message": "Logged in.", "user": { "id": 1, "username": "w.madzorera", "role": "doctor", "tier": "pro" } }
```
Response (MFA enabled):
```json
{ "mfa_required": true }
```

### POST /auth/mfa-verify
```json
{ "code": "123456" }
```
MFA verification is limited to 5 requests per minute and locks the account
after repeated invalid codes.

---

## Records  `/records`

| Method | Route                              | Roles               |
|--------|------------------------------------|---------------------|
| GET    | /records/patients                  | All                 |
| POST   | /records/patients                  | Admin, Doctor, RO   |
| GET    | /records/patients/<id>             | All                 |
| PUT    | /records/patients/<id>             | Admin only         |
| DELETE | /records/patients/<id>             | Admin only         |
| POST   | /records/patients/<id>/records     | Admin, Doctor       |
| GET    | /records/<id>                      | All                 |
| PUT    | /records/<id>                      | Admin, Doctor       |
| DELETE | /records/<id>                      | Admin only          |
| POST   | /records/<id>/break-glass          | Doctor, Admin       |

`GET /records/patients/<id>` returns the patient profile and decrypted medical
records for the authorized user. Updating or removing a patient is restricted
to admins; removing a patient also removes their associated medical records
and writes an audit entry.

Login is limited to 5 requests per minute. Break-glass access is limited to 3
requests per minute. Break-glass state is recorded on the audit entry only;
the medical record is not permanently marked as break-glass.

### POST /records/patients/<id>/records
Sensitive fields are encrypted at rest using the caller's tier algorithm.
```json
{
  "record_type": "consultation",
  "diagnosis": "Hypertension stage 2",
  "notes": "Patient reports headaches for 3 weeks.",
  "prescription": "Amlodipine 5mg once daily"
}
```

### POST /records/<id>/break-glass
Emergency access override. Fully logged and flagged for security review.
```json
{ "reason": "Patient unconscious, no attending physician available." }
```

## Privacy and Governance  `/privacy`

| Method | Route                                      | Auth                  |
|--------|--------------------------------------------|-----------------------|
| GET    | /privacy/retention-policy                  | Authenticated         |
| GET    | /privacy/export/patients/<id>              | Staff role            |
| GET    | /privacy/data-export                       | Admin                 |
| POST   | /privacy/erasure-requests                  | Staff role            |
| GET    | /privacy/erasure-requests/<id>             | Staff role            |
| GET    | /privacy/admin/erasure-requests            | Admin                 |
| POST   | /privacy/admin/erasure-requests/<id>/decision | Admin              |
| GET    | /privacy/admin/retention/preview           | Admin                 |
| POST   | /privacy/admin/retention/purge             | Admin                 |
| PUT    | /privacy/admin/patients/<id>/legal-hold    | Admin                 |
| GET    | /privacy/admin/incidents                   | Admin                 |
| POST   | /privacy/admin/incidents                   | Admin                 |
| PUT    | /privacy/admin/incidents/<id>              | Admin                 |

The default retention period is 7 years and can be configured with
`RECORD_RETENTION_YEARS`. Legal holds exclude records from automated purge.
See [DATA_GOVERNANCE.md](DATA_GOVERNANCE.md) for the retention and right-to-erasure
workflow and [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) for breach response and
notification procedures.

### POST /privacy/erasure-requests
```json
{ "patient_id": 42, "reason": "Verified data-subject erasure request." }
```

### POST /privacy/admin/erasure-requests/<id>/decision
```json
{ "decision": "approve", "note": "Identity verified; no statutory retention exception applies." }
```

### PUT /privacy/admin/patients/<id>/legal-hold
```json
{ "retention_hold": true }
```

### POST /privacy/admin/incidents
```json
{ "title": "Suspected credential compromise", "summary": "...", "severity": "high" }
```

---

## Subscriptions  `/subscriptions`

| Method | Route                       | Auth |
|--------|-----------------------------|------|
| GET    | /subscriptions/tiers        | No   |
| GET    | /subscriptions/me           | Yes  |
| GET    | /subscriptions/billing-history | Yes |
| POST   | /subscriptions/upgrade      | Yes  |
| POST   | /subscriptions/cancel       | Yes  |

### POST /subscriptions/upgrade
```json
{
  "tier": "pro",
  "billing_period": "annual",
  "provider": "stripe",
  "payment_reference": "pi_..."
}
```

Tier pricing is billed per organization. Monthly and annual prices are returned by
`GET /subscriptions/tiers`; annual Pro and Enterprise plans include a 17% discount
and 2 months free. The Free tier is $0 monthly and annually with limited access.
Paid upgrades are activated only after the configured provider verifies the
provider-issued payment reference against the expected amount, currency, tier,
and billing period. Card details are never sent to or stored by VaultWard.

## Integrations `/integrations`

| Method | Route                                  | Auth |
|--------|----------------------------------------|------|
| GET    | /integrations                          | Yes  |
| POST   | /integrations/api-keys                 | Yes  |
| POST   | /integrations/api-keys/<id>/revoke     | Yes  |

API keys are returned only at creation time, stored as SHA-256 hashes, limited
to the requested scopes, and revocable by their owner. Supported scopes are
`records:read`, `records:write`, and `patients:read`.

---

## Admin  `/admin`  (admin role only)

| Method | Route                       | Description                         |
|--------|-----------------------------|-------------------------------------|
| GET    | /admin/users                | List all users                      |
| POST   | /admin/users                | Create user                         |
| PUT    | /admin/users/<id>           | Update role/tier/status             |
| GET    | /admin/audit                | Paginated audit log                 |
| DELETE | /admin/audit/<id>           | Remove an audit log (password required) |
| GET    | /admin/audit/verify-chain   | Verify tamper-evident hash chain    |
| GET    | /admin/stats                | Dashboard summary stats             |

### GET /admin/audit/verify-chain
Returns `"intact"` or `"COMPROMISED"` with the id of the broken entry.

---

## Health and Maintenance

### GET /healthz

Unauthenticated uptime and dependency check. Returns `200` when database,
encryption, and maintenance checks are healthy; returns `503` with
`"status": "degraded"` when a check fails or rotation is due.

```json
{
  "status": "ok",
  "checks": {
    "database": "ok",
    "encryption": "ok",
    "maintenance": "ok"
  }
}
```

### Admin maintenance routes

| Method | Route                         | Description |
|--------|-------------------------------|-------------|
| POST   | /admin/maintenance/backup     | Create an encrypted SQLite `.vwb` backup |
| POST   | /admin/maintenance/restore    | Restore a named `.vwb` after integrity validation |
| POST   | /admin/maintenance/rotate-keys | Immediately rotate Pro and Enterprise keys |

Restore example:
```json
{ "filename": "vaultward-2026-09-11T120000.vwb" }
```

The scheduler runs in the application process, creates backups, and rotates
Pro keys after 90 days and Enterprise keys after 30 days by default. Configure
`VAULTWARD_BACKUP_DIR`, `PRO_KEY_ROTATION_DAYS`,
`ENTERPRISE_KEY_ROTATION_DAYS`, `MAINTENANCE_INTERVAL_SECONDS`, and
`ENABLE_MAINTENANCE_SCHEDULER` through the environment.

---

## Encryption tiers

| Tier       | Algorithm    | Key rotation | Hash-chained audit | Price     |
|------------|--------------|-------------|---------------------|-----------|
| Free       | AES-128-GCM  | None        | No                  | $0        |
| Pro        | AES-256-GCM  | 90 days     | Yes                 | $14.99/mo |
| Enterprise | AES-256-GCM  | 30 days     | Yes                 | $49.99/mo |
