# THREATS.md

Status: **Closed** = mitigated and covered by a test. **Accepted** = knowingly left, with the reason.
Tests are in `test/security.test.js` (test names quoted).

## Closed

| # | Threat | What I did | Test |
|---|--------|-----------|------|
| 1 | **IDOR**: guess/enumerate a document id | One function, `authorize()` (src/authz.js), is called by every document route. Ids are random UUIDs, but security does not depend on that. | "a user with no grant cannot read, download, edit…" |
| 2 | **Existence leak** via 403 vs 404 | No-grant and not-found return the same status and body. Only a user who *already* holds a grant gets 403 for an action above their level. | '"not found" and "not granted" are indistinguishable' |
| 3 | **Privilege escalation: viewer/owner calling admin routes** | `requireRole('admin')` on the whole admin router; checked server-side from the DB role, never from the client. | "non-admins cannot reach admin endpoints" |
| 4 | **Read-grant holder editing/deleting/re-sharing** | Actions map to a required level (read < edit < owner). Only the owner can delete or share. | "a read grant allows download but not edit…", "an edit grant can edit but still cannot…" |
| 5 | **Mass assignment** (set own role, owner_id, sha256, deleted_at) | Role is never read from registration input. PATCH uses an explicit field allow-list. | "role cannot be chosen at registration", "PATCH cannot reassign ownership" |
| 6 | **Stale access after revocation** | No grants or roles are embedded in tokens. Sessions are opaque random tokens; the session, user status and grant are all re-read from the DB on every request. | "revoking a grant works IMMEDIATELY…" |
| 7 | **Disabled/fired user's session still works** | Disabling deletes their sessions *and* the auth middleware rejects inactive users. | "disabling a user kills their existing session immediately" |
| 8 | **Deleted document still reachable** | `authorize()` excludes soft-deleted rows; blob is removed from disk; grants deleted. | "deleting a document makes it unreachable…" |
| 9 | **Owner A managing owner B's document** | Grant management goes through `authorize(..., 'share')`, which requires owner level on *that* document. | "an owner cannot grant on, or touch, another owner's document" |
| 10 | **Search/metadata leakage** | The permission filter is inside the SQL query, so unreachable documents are never selected, counted or sorted. LIKE wildcards are escaped. | "search never returns, or counts…", "search supports category…" |
| 11 | **SQL injection** | Parameterised queries everywhere. | "SQL injection in search and login…" |
| 12 | **Path traversal via filename** | Uploaded filename is display-only and sanitised. On disk the name is a server-generated UUID; the blob name is regex-checked again before read. | "upload validation…", "download is an attachment…" |
| 13 | **Malicious upload / type spoofing** | Allow-list of extensions, magic-byte check, 10 MB cap, empty-file rejection. Mime type comes from our table, not the client. | "upload validation…" |
| 14 | **Stored XSS via filename/content** | Downloads are `Content-Disposition: attachment` with `nosniff`; API is JSON-only; CSP `default-src 'self'`. | "download is an attachment with nosniff…" |
| 15 | **Direct blob access** | Blobs live outside any served directory, mode 0600; the only read path is the authorised download route. No signed/long-lived links exist to outlive a revocation. | "…the stored blob is not web-reachable" |
| 16 | **Audit tampering (edit/delete rows)** | SQLite triggers abort UPDATE/DELETE on `audit`. Each row stores a SHA-256 hash of its content plus the previous row's hash; `/api/admin/audit/verify` walks the chain. | "audit: rows cannot be updated…", "audit: even with the triggers dropped…" |
| 17 | **Refused attempts not recorded** | Every denial (document, role, login, upload) writes an audit row with the *real* reason, even though the client sees a generic 404. | "a user with no grant…" (checks the audit row) |
| 18 | **Credential brute force / user enumeration** | bcrypt, 5 failures → 15-minute lock, bcrypt runs against a dummy hash for unknown emails, same error for every failure. | "login lockout after repeated failures…" |
| 19 | **Admin abuse of content** | Admin has no document access path at all: cannot download/read, cannot be granted access. Admin *actions* (role changes, disables) are audited. | "an admin sees metadata… but cannot read document content" |
| 20 | **Unauthenticated access to anything** | `requireAuth` on every route except register/login. | "every document and admin route rejects unauthenticated callers" |
| 21 | **Simultaneous audit write corruption / forking** | Serialized writes via `BEGIN IMMEDIATE` transactions in SQLite ensuring strict linear blockchain sequence. | "concurrency: simultaneous parallel audit writes preserve hash chain integrity" |
| 22 | **Audit tail truncation by raw DB access** | External anchor head export (`POST /api/admin/audit/anchor`) and verification (`GET /api/admin/audit/anchor`). | "external audit anchor: anchoring head and detecting tail truncation" |
| 23 | **Accidental content overwrite data loss** | Immutable historical version tracking in `document_versions` table and rollback endpoint (`POST /api/documents/:id/rollback/:version`). | "document versioning: uploading, replacing content, listing versions..." |
| 24 | **Token theft from browser local storage** | httpOnly + SameSite=Strict session cookies alongside CSRF verification tokens for state-modifying requests. | "session security: httpOnly cookie auth and CSRF protection" |

## Accepted (known weaknesses)

| # | Threat | Why I left it |
|---|--------|---------------|
| A1 | **Someone with raw DB write access can drop the audit triggers and rewrite the *tail* of the log** (truncation of the newest rows is not detectable from inside the DB). | **Mitigated**: External chain anchoring (`/api/admin/audit/anchor`) allows external verification. An external monitoring agent should periodically pull the anchor head. |
| A2 | **A user with a legitimate read grant can copy the file** before revocation. | Cannot be solved by software that hands over the bytes. Revocation stops *future* access; the audit log shows exactly what was downloaded (with sha256). |
| A3 | **Grant-by-email reveals whether an email is registered** (404 "user not found") to document owners. | Owners need to share by name/email. Limited to authenticated owners and audited. Fix later: invite-by-email flow. |
| A4 | **Bearer token in JS-readable storage if a UI stores it in localStorage** (XSS would steal it). | **Mitigated**: The API now issues `httpOnly; SameSite=Strict` session cookies with CSRF token verification on state-changing methods. Bearer tokens remain supported for external scripts. |
| A5 | **Login lockout can be used to lock a victim out** (account-level lock). | Chosen over per-IP limiting because attackers rotate IPs. Lock is 15 min, and audited. |
| A6 | **No per-IP rate limit on other endpoints**, no virus scanning, no encryption at rest. | Out of scope for the week. Host-level disk encryption and a reverse-proxy rate limit are the intended answers. |
| A7 | **Single-process SQLite**: no horizontal scaling. | The audit chain relies on serialised writes (`BEGIN IMMEDIATE`). Moving to Postgres would need an advisory lock for the same guarantee. |

## Not yet tested / unfinished
- Concurrency test for simultaneous audit writes: **RESOLVED & TESTED** (covered in test suite).
- Document versions and recovery: **RESOLVED & TESTED** (supported via version history and rollback).
- External sharing links (deliberately **not built**: they make "revocation is immediate" much harder to guarantee).
