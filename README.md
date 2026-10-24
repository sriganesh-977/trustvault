# TrustVault

TrustVault is a Node.js/Express document vault with server-enforced, per-document permissions. The dashboard is not an authorization boundary: every list, file, edit, delete, and permission route checks current database state.

## Live demo

<https://trustvault-demo-6mq6.onrender.com>

The demo contains fictional documents and seeded accounts. Do not upload real or confidential files. It is hosted on Render Free: the service sleeps after inactivity and the filesystem is ephemeral, so uploaded files, the SQLite database, and local encryption key can be lost on spin-down, restart, or redeploy.

| Role | Email | Password | Scope |
|---|---|---|---|
| Administrator | `admin@trustvault.test` | `Admin-Demo-Pass-1` | Manage users and audit metadata. |
| Document owner | `owner@trustvault.test` | `Owner-Demo-Pass-1` | Upload, edit, grant/revoke, and delete owned documents. |
| Viewer | `viewer@trustvault.test` | `Viewer-Demo-Pass-1` | View documents explicitly granted to the account. |

## Run locally

```powershell
npm ci
$env:TRUSTVAULT_DEMO = "1"
npm start
```

Open <http://127.0.0.1:3000>. The first run creates the SQLite database and private blob directory under `DATA_DIR` (default `./data`). Set `TRUSTVAULT_DEMO=0` to disable seed accounts.

## Permission model

Grants are direct to named, already-provisioned accounts; there is no folder inheritance. `read` permits list visibility and file download. `edit` also permits metadata and file replacement. Only the workspace `admin` and the document `owner` can grant/revoke permissions or soft-delete the document. Admins can read/edit/delete all non-deleted documents. The server checks each request. A committed revocation is effective for the next request; it cannot retract bytes already downloaded or cancel a response already in flight.

## API and database

- [API.md](API.md) documents every route and its caller permissions.
- The database schema is created and migrated by [src/db.js](src/db.js).
- [THREATS.md](THREATS.md) records attacks considered, mitigations, tests, and accepted gaps.
- [PROMPTS.md](PROMPTS.md) records dated AI prompts, issues caught, and fixing commits.
- [SUBMISSION.md](SUBMISSION.md) summarizes design choices and unfinished work.

## Tests

```powershell
npm test
```

The suite exercises role boundaries across listing, download, edit, replacement, delete, and grant routes; immediate revocation; expired grants; search scoping; upload validation; signed audit tampering; MFA replay; and login throttling. If an authorization check is removed, the corresponding cross-role assertion should fail.

## Security construction and limitations

- Passwords use bcrypt. Sessions are random opaque identifiers stored as hashes with an expiry; state-changing routes require CSRF tokens. MFA uses TOTP. Five failed login attempts trigger a temporary lockout.
- Uploads are capped at 20 MB and restricted by magic-byte validation to supported text, PDF, PNG, and JPEG files. Filenames are sanitized and blobs are stored outside the public web root. This is not malware scanning or content disarm.
- Audit entries form a SHA-256 chain and have SQLite append-only triggers. A database-only attacker cannot silently edit an event without detection. A compromised application process can forge events. External anchoring is available through the admin audit controls.
- A `document.read` event proves the server authorized and returned a file response, not that a human read or retained the bytes.
- Soft delete revokes access immediately but retains encrypted content; no restore or permanent purge endpoint exists.
- There is no self-service account invitation, email verification, password reset, MFA recovery, SSO, multi-tenant isolation, malware scanning, tested backup/restore, or key rotation workflow. Do not use this build for real confidential documents until those needs are implemented and independently reviewed.

## Production startup guard

Set `TRUSTVAULT_DEMO=0`, `TRUSTVAULT_COOKIE_SECURE=1`, and `DATA_DIR` to durable storage in production. Configure OAuth secrets only through the host secret manager. Never commit production credentials. `GET /healthz` is the host health-check endpoint.
