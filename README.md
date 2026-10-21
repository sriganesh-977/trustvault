# TrustVault

TrustVault is a local secure-document-sharing prototype. Its core boundary is server-side authorization on each document request: owners and explicitly granted accounts can retrieve a file; everyone else receives the same `404` response. Grants are scoped to one document, may expire, and can be revoked.

## Run locally

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
```

Open <http://127.0.0.1:8000>.

The first start creates a local demo database and an encryption key in `data/`. Demo accounts:

- Administrator: `admin@trustvault.local` / `VaultDemo!2026`
- Member: `maya@northstar.example` / `Northstar!2026`

The member account has direct access to the Northstar agreement only. Use the administrator account to inspect the audit trail, upload files, grant access, and revoke it. The sample records and file contents are fictional.

## Checks

```powershell
python -m pytest -q
```

The tests cover document-level authorization, direct grants, revocation, denied-access events, audit-chain verification, and append-only audit rows.

## Security model and limits

- Uploaded file bytes are encrypted with Fernet before they are stored in SQLite. The encryption key is generated once under `data/master.key`; protect and back up that key separately from the database. `TRUSTVAULT_ENCRYPTION_KEY` can provide a managed Fernet key instead.
- Set `TRUSTVAULT_DATA_DIR` before starting the server to choose a different database/key directory.
- Passwords use PBKDF2-HMAC-SHA256 with per-user random salts. Session identifiers are random, stored only as hashes in the database, and sent in `HttpOnly`, `SameSite=Strict` cookies. Mutating requests require a CSRF token.
- Every successful file delivery attempt, denied request, share, revocation, and sign-in event is recorded. Audit events form a SHA-256 hash chain and database triggers reject ordinary row updates/deletes. The file event proves the server authorized and delivered a response; it cannot prove that a human read or retained the bytes.
- The chain detects changes within the retained database, but it is not independent proof against a privileged operator who can rewrite the database and recompute hashes. Production deployments should anchor signed checkpoints to separately controlled, immutable storage.
- This prototype is not production-ready identity or key management: it has seeded demo credentials, no MFA, no rate limiting, no organization/tenant isolation, and no external identity provider. Use HTTPS, managed secrets and key rotation, backups, malware scanning, rate limits, account provisioning and offboarding controls, monitoring, and independent audit anchoring before handling real documents.
- Set `TRUSTVAULT_COOKIE_SECURE=1` behind HTTPS. Do not expose the development server directly to the internet.
