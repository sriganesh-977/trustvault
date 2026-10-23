# TrustVault

Secure document sharing where only people who were granted a document can reach it, and every attempt (allowed or refused) is recorded in a tamper-evident audit trail.

Stack: Node 20+, Express, SQLite (better-sqlite3). Run `npm test` for the security suite (28 tests).

## Run it
```bash
npm ci
npm run seed      # creates one demo account per role (see below)
npm start         # http://localhost:3000
```
Visit `http://localhost:3000` in your web browser to open the interactive **TrustVault Web UI Dashboard**!
Quick demo sign-in buttons are available on the login screen for `admin`, `owner`, and `viewer`.
Env: `PORT`, `DATA_DIR` (default `./data`), `DB_PATH`, `TRUST_PROXY=1` when behind a proxy (so audit IPs are right).

### Social sign-in

The sign-in page supports Google and Microsoft OAuth. Configure these as deployment secrets; never commit the client secrets:

- Google: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, optional `GOOGLE_REDIRECT_URI`
- Microsoft: `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, optional `MICROSOFT_TENANT_ID` and `MICROSOFT_REDIRECT_URI`

If redirect URI variables are omitted, use `https://<your-host>/api/auth/oauth/google/callback` and `https://<your-host>/api/auth/oauth/microsoft/callback` in the provider consoles.
Seed passwords can be overridden with `SEED_ADMIN_PW`, `SEED_OWNER_PW`, `SEED_VIEWER_PW`.

Demo credentials (seed data, change on any real deployment):
| Role | Email | Password |
|---|---|---|
| admin | admin@trustvault.test | Admin-Demo-Pass-1 |
| owner | owner@trustvault.test | Owner-Demo-Pass-1 |
| viewer | viewer@trustvault.test | Viewer-Demo-Pass-1 |

## Permission model (in my words)
- **Roles** (global): `admin` manages users and sees activity/metadata, with **no access to document content**. `owner` can upload documents and manage who can access them. `viewer` can only use documents granted to them. Self-registration always creates a viewer; an admin promotes.
- **Per-document access**: the uploader is that document's owner. Others get an explicit grant: `read` (view + download) or `edit` (also rename/recategorise/replace content). Only the document owner can delete or grant/revoke. No groups or folder inheritance (deliberately; fewer ways to get it wrong).
- **One decision point**: `authorize()` in `src/authz.js`, called by every document route; it re-reads the DB every time, so revocation is instant. Tokens carry no permissions.
- Auth: opaque random session token (`Authorization: Bearer <token>`), stored hashed, 8 h expiry, revocable.

## API: who may call what
`any` = any authenticated user, `doc:X` = must hold at least X on that document (owner > edit > read). All failures on documents return 404 unless the caller holds a lower grant (then 403). Every call is audited.

| Endpoint | Who |
|---|---|
| `POST /api/auth/register` | public (creates a viewer) |
| `POST /api/auth/login` | public (5 failures → 15 min lock) |
| `POST /api/auth/logout`, `GET /api/me` | any |
| `POST /api/documents` (multipart `file`, optional `name`, `category`) | role `owner` |
| `GET /api/documents?q=&category=&owner=&from=&to=` | any (results limited to documents you can reach) |
| `GET /api/documents/:id` | doc:read |
| `GET /api/documents/:id/download` | doc:read |
| `PATCH /api/documents/:id` (`name`, `category`) | doc:edit |
| `PUT /api/documents/:id/content` (multipart `file`) | doc:edit |
| `DELETE /api/documents/:id` | doc:owner |
| `GET /api/documents/:id/versions` | doc:read |
| `GET /api/documents/:id/versions/:version/download` | doc:read |
| `POST /api/documents/:id/rollback/:version` | doc:edit |
| `GET/POST /api/documents/:id/grants` (`email`, `level`) | doc:owner |
| `DELETE /api/documents/:id/grants/:userId` | doc:owner |
| `GET /api/admin/audit?action=&outcome=&document=&actor=&before=&limit=` | role `admin` |
| `GET /api/admin/audit/verify` | role `admin` |
| `GET/POST /api/admin/audit/anchor` | role `admin` |
| `GET /api/admin/alerts` | role `admin` |
| `GET /api/admin/documents` (metadata only) | role `admin` |
| `GET /api/admin/users`, `PATCH /api/admin/users/:id` (`role`, `active`) | role `admin` |

## Docs
- `THREATS.md`: threats, what was done, what was knowingly accepted
- `PROMPTS.md`: AI usage log
- Schema: `src/db.js` (created automatically on start; no migration step)
