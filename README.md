# VaultWard

Encrypted hospital records platform with tiered encryption subscriptions.

## Structure
```
vaultward/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── config.py            # Config (DB URI, secret keys, tier settings)
│   ├── models/
│   │   ├── user.py          # User, Role
│   │   ├── patient.py       # Patient, MedicalRecord
│   │   ├── subscription.py  # Subscription, Tier
│   │   └── audit.py         # AuditLog (hash-chained)
│   ├── crypto/
│   │   ├── engine.py        # Tier-aware encrypt/decrypt dispatcher
│   │   ├── aes.py           # AES-128 / AES-256-GCM implementations
│   │   └── keys.py          # Key derivation (Argon2/PBKDF2) + storage
│   ├── routes/
│   │   ├── auth.py          # Login, MFA, logout
│   │   ├── records.py       # CRUD for medical records
│   │   ├── subscriptions.py # Tier upgrade/downgrade
│   │   └── admin.py         # Admin dashboard endpoints
│   ├── utils/
│   │   └── decorators.py    # @require_role, @require_tier
│   ├── templates/
│   │   └── login.html       # UI (yellow/teal glow theme)
│   └── static/
├── requirements.txt
└── run.py
```

## Build order
1. `models/user.py` + `routes/auth.py` — login works, no encryption yet
2. `models/patient.py` — plain CRUD on records
3. `crypto/keys.py` + `crypto/aes.py` — encryption primitives, unit tested standalone
4. `crypto/engine.py` — wires tier → algorithm
5. `models/subscription.py` + `utils/decorators.py` — tier gating
6. `models/audit.py` — hash-chained audit log
7. MFA + break-glass access

## Quick start
1. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the app from the project root:
   ```bash
   python run.py
   ```
   or:
   ```bash
   python server.py
   ```
3. Open the site in your browser:
   ```
   http://localhost:3452/
   ```

## Login notes
- Use the Flask server URL above; the UI will not work if you open `login.html` directly from the file system.
- No default credentials are seeded. Provision an admin explicitly with `VAULTWARD_ADMIN_USERNAME`, `VAULTWARD_ADMIN_PASSWORD`, and optionally `VAULTWARD_ADMIN_EMAIL` before starting the app.
- If the app shows a network error, the backend is not running or the page was opened as a local file.

## Production secrets
- `ProductionConfig` fails closed unless `SECRET_KEY` and `VAULTWARD_MASTER_SECRET` are present before the app is imported.
- In production, inject both values from the deployment platform's real secret manager into the process environment. The application does not read production secrets from `.env` or a checked-in file.
- For local development only, use the ignored `.env` file.

## Resilience and key management

- `GET /healthz` is an unauthenticated health check for uptime monitoring. It checks database connectivity, master-secret availability, and whether scheduled key rotation is due.
- The maintenance scheduler creates encrypted SQLite backups in `BACKUP_DIR` (default: `backups/`) and rotates Pro keys every 90 days and Enterprise keys every 30 days.
- In multi-worker production, serve the app with `gunicorn "wsgi:app" --workers 4 --bind 0.0.0.0:8000` and run one separate `python maintenance_worker.py` process. Production web workers do not start the scheduler.
- Backup files use the `.vwb` format: the SQLite snapshot is encrypted with AES-256-GCM using a key derived from `VAULTWARD_MASTER_SECRET` and a per-backup salt. The payload also includes a SHA-256 integrity check.
- Administrators can create a backup with `POST /admin/maintenance/backup`, restore a named backup with `POST /admin/maintenance/restore`, and manually rotate keys with `POST /admin/maintenance/rotate-keys`.
- Test restore procedures against a disposable environment before using a backup in production. A restore replaces the active SQLite database; preserve the current database and obtain an approval before running it.
- Versioned Pro and Enterprise keys are wrapped by the master-derived wrapping key. Existing ciphertext remains readable through its recorded key version, while scheduled rotation re-encrypts current records under a new version.

See [API_REFERENCE.md](API_REFERENCE.md) for request examples and [tests/test_resilience.py](tests/test_resilience.py) for the tested backup/restore and rotation procedure.
