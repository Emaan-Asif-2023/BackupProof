# BackupProof – Member A part (auth, RBAC, backup catalogue)

Flask + SQLite. Runs locally from VS Code, no Docker needed.

## Setup (Windows PowerShell shown; on Linux/macOS use `source .venv/bin/activate`)

```powershell
cd backupproof
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

flask --app app init-db
flask --app app seed-demo          # prints random passwords for admin / operator / viewer (shown once)
# or create your own first admin:
flask --app app create-user alice admin

python run.py                      # http://127.0.0.1:5000
python -m pytest -q                # run the tests
```

## Roles (enforced on the server)

| Action                                   | Viewer | Operator | Admin |
|------------------------------------------|:------:|:--------:|:-----:|
| View catalogue, assets, backup details   |   ✔    |    ✔     |   ✔   |
| Create assets, upload / register backups |        |    ✔     |   ✔   |
| Delete assets / backups                  |        |          |   ✔   |
| Manage users and roles                   |        |          |   ✔   |

## Layout

```
app/__init__.py   app factory, error handlers, CLI commands
app/security.py   CSRF, rate limiter, current-user loading, role decorators, headers
app/services.py   validation + business rules (shared by pages and API)
app/api.py        JSON API  (/api/...)
app/pages.py      server-rendered pages
app/audit.py      append-only audit writer
schema.sql        users, assets, backups, audit_log (+ append-only triggers)
fixtures/         safe sample files for "register" (approved source folder)
tests/            41 automated tests
```

## JSON API

All state-changing calls need the `X-CSRF-Token` header (get it from `GET /api/csrf`, and a fresh one is returned by login).
Errors always look like `{"error": {"code": "...", "message": "..."}}`.

| Method & path                  | Role            |
|--------------------------------|-----------------|
| GET `/api/csrf`                | public          |
| POST `/api/login`, `/api/logout`, GET `/api/me` | public / any |
| GET/POST `/api/users`, PATCH `/api/users/<id>` | admin |
| GET `/api/assets`, POST `/api/assets` | any / operator+ |
| DELETE `/api/assets/<id>`      | admin           |
| GET `/api/backups?q=&asset_id=`, GET `/api/backups/<public_id>` | any |
| POST `/api/backups` (multipart: file, asset_id, retention_days, notes) | operator+ |
| POST `/api/backups/register` (json: source_file, asset_id, retention_days, notes) | operator+ |
| DELETE `/api/backups/<public_id>` | admin        |

## Security decisions (for your report / threat model)

- Passwords: Werkzeug scrypt/PBKDF2 hashes, 10+ chars with letters and digits; login error is identical for unknown user / wrong password / locked account; dummy hash check equalises timing.
- Lockout: 5 failed attempts (configurable) locks the account for 5 min; plus per-IP rate limit on login/upload/register.
- Sessions: signed cookie, HttpOnly, SameSite=Lax, 30-minute expiry; user and role are re-read from the DB each request, so disabling a user or changing a role takes effect immediately; login rotates the session and CSRF token.
- CSRF: per-session token required on every non-GET request (form field or `X-CSRF-Token`).
- Authorization: `roles_required(...)` on each route; denials return a generic 403 and are written to the audit log. Last active admin cannot be removed.
- Uploads: extension allow-list, magic-byte/NUL check, 25 MB cap, empty files rejected, stored under a server-generated UUID name (user filename is display-only), file mode 0600, SHA-256 computed while streaming.
- Register: only plain names that are listed in `fixtures/` are accepted, which rules out path traversal.
- SQL: all queries parameterised; LIKE wildcards escaped. IDs in URLs are server-generated 32-hex values.
- Output: Jinja auto-escaping; CSP forbids inline scripts/styles; `nosniff`, `X-Frame-Options: DENY`, `no-store`.
- Errors: stable codes, no stack traces. Audit log is append-only (DB triggers block UPDATE/DELETE) and never stores passwords or file contents.

## Hooks for teammates

`backups.sha256` is the baseline checksum for integrity verification, `backups.status` (default `registered`) can be set by the verifier, `backups.retention_days` + `created_at` give the retention expiry, and `app.audit.log(action, outcome, target, detail)` is the one function everyone should use for audit events.

## Known limitations

In-memory rate limiter resets on restart and is per process. Set `SESSION_COOKIE_SECURE=True` when served over HTTPS. No password-change screen yet.
