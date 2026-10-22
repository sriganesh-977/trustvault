# PROMPTS.md

> Rules from the brief: at least 5 **dated** entries, at least 2 about authorisation / access control / audit.
> Each entry: what I asked, what it produced, what was **specifically wrong**, what I did instead (link the fixing commit).
> "It was all fine" is not an entry. Write these AS YOU GO, from real sessions only.

## Entry template

### YYYY-MM-DD: short title
- **Asked:** (prompt or fair summary)
- **Produced:** 
- **Wrong because:** (be specific: which line, what attack it enables)
- **Did instead:** (what I changed) — commit: `<hash or URL>`
- **How I checked:** (test name / manual attack)

## Reused prompts / context files

### System Prompt & Security Checklist (Reused across sessions)
```markdown
You are a senior security engineer and architect building TrustVault.
Adhere strictly to the following security guidelines:
1. Zero Trust: Every request must be authenticated and authorized against the database at runtime. Tokens must never carry grants.
2. Anti-Enumeration: Missing resources and ungranted resources must return identical 404 responses.
3. Least Privilege: Global roles (admin, owner, viewer) must never grant document content access to admins.
4. Content Validation: Determine file types via magic bytes, never client-supplied MIME headers or uninspected extensions.
5. Audit Integrity: Audit log is append-only with SQLite triggers AND SHA-256 hash chaining. Transactions must be serialized with immediate write locks.
6. Defense-in-Depth: Enforce security headers (CSP, nosniff, cache-control: no-store), attachment downloads, password bcrypt with constant-time dummy comparisons, and CSRF protection for cookie sessions.
```

## Entries

### 2026-10-18: Centralized Authorization & Existence Probe Leakage (404 vs 403)
- **Asked:** Implement the centralized authorization decision function and document route guard for `GET /api/documents/:id`.
- **Produced:** A guard function that returned `404 Not Found` if a document record was not found in SQLite, but returned `403 Forbidden` whenever a document was found but the requesting user had no grant in `grants` table.
- **Wrong because:** In `src/app.js` and `src/authz.js`, returning `403` vs `404` creates an IDOR / existence oracle enumeration vulnerability. An unprivileged attacker can probe random UUIDs or sequential IDs and confirm the existence of confidential files owned by others purely by distinguishing between 404 and 403 status codes.
- **Did instead:** Refactored `guard()` and `authorize()` so that a caller who holds no grant on a document receives the exact same response status (`404`) and body (`{"error": "not found"}`) as if the document did not exist. A `403 Forbidden` response is only returned if the caller already possesses a valid grant on that document, but attempts an action beyond their permitted tier (e.g. `read` grant holder attempting `edit` or `delete`).
- **How I checked:** Test `test('"not found" and "not granted" are indistinguishable to the caller')` in `test/security.test.js`.

### 2026-10-18: User Enumeration via Password Verification Timing Side-Channel
- **Asked:** Implement `POST /api/auth/login` with bcrypt verification and account lockout after 5 failed attempts.
- **Produced:** An endpoint that queried `SELECT * FROM users WHERE email=?`. If no user was found, it immediately returned `401 {"error": "invalid credentials"}` without running `bcrypt.compareSync`.
- **Wrong because:** `bcrypt.compareSync` with cost factor 12 takes ~80-120ms of CPU time. When an unregistered email was submitted, the server responded in <1ms, whereas for registered accounts it responded in >80ms. This created a high-precision timing oracle that allowed unauthenticated remote attackers to enumerate valid email addresses across the company.
- **Did instead:** Generated a static `DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', COST)` at application bootstrap in `src/app.js`. In `/api/auth/login`, `bcrypt.compareSync(pw, u ? u.password_hash : DUMMY_HASH)` is always executed regardless of whether the user exists. This guarantees that timing characteristics are indistinguishable between valid and invalid emails.
- **How I checked:** Test `test('login lockout after repeated failures, and failed attempts are audited')` and measured response times across present and non-existent users.

### 2026-10-19: Audit Log Forking Under Concurrent Requests
- **Asked:** Implement tamper-evident cryptographic chaining in `src/audit.js` using SHA-256.
- **Produced:** A function `record(db, entry)` that executed `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`, calculated `digest(prev_hash, entry)`, and executed `INSERT INTO audit ...` using standard SQLite deferred transaction mode.
- **Wrong because:** Under concurrent HTTP requests (e.g. simultaneous downloads or parallel login attempts), two or more threads/processes read the same `prev_hash` before any of them completed their `INSERT`. This caused conflicting rows with identical `prev_hash` values, breaking the strictly linear blockchain and causing future `audit.verify(db)` verification walks to fail.
- **Did instead:** Wrapped the entire read-hash-write sequence inside an immediate transaction: `const run = db.transaction(() => { ... }); run.immediate();`. SQLite's `BEGIN IMMEDIATE` guarantees exclusive write access at the start of the transaction before reading the tail hash, serializing all audit appends and preventing any chain fork.
- **How I checked:** Test `test('concurrency: simultaneous parallel audit writes preserve hash chain integrity')` firing 30 simultaneous asynchronous requests.

### 2026-10-19: MIME Type Spoofing and Path Traversal in Upload Handler
- **Asked:** Add document upload support with `multer` and validate file types.
- **Produced:** A handler that validated `req.file.mimetype` against an allowlist and used `path.join(blobDir, req.file.originalname)` to write the file directly to disk.
- **Wrong because:** 
  1. The client controls `req.file.mimetype` and can upload an HTML/SVG/executable script claiming it is `application/pdf`, enabling stored Cross-Site Scripting (XSS) or Remote Code Execution.
  2. Trusting `req.file.originalname` directly allows directory traversal payloads (e.g. `../../etc/passwd` or `../../../public/shell.js`) that escape the intended storage root.
- **Did instead:** 
  1. Built `inspectUpload()` in `src/upload.js` that inspects file content magic bytes (e.g. `%PDF-` for PDF, `\x89PNG` for PNG, `PK\x03\x04` for Office ZIP formats, valid UTF-8 for TXT).
  2. Implemented `safeName()` to sanitize filenames for display only.
  3. Stored blobs strictly under server-generated UUIDs (`crypto.randomUUID()`) outside the web root with restrictive `0o600` file permissions.
- **How I checked:** Tests `test('upload validation: bad type, spoofed content, empty file, oversize, hostile filename')` and `test('download is an attachment with nosniff, and the stored blob is not web-reachable')`.

### 2026-10-20: Audit Log Tail Truncation Attack & External Anchoring
- **Asked:** Ensure the audit log cannot be modified even by an attacker who gains direct database privileges.
- **Produced:** SQLite database triggers `audit_no_update` and `audit_no_delete` that abort any SQL UPDATE or DELETE queries.
- **Wrong because:** An attacker with database admin access (or direct filesystem access to `trustvault.db`) can execute `DROP TRIGGER audit_no_delete; DELETE FROM audit WHERE seq >= X;`. Because the internal hash chain is validated from sequence 1 forward, truncating the newest records leaves the internal chain mathematically consistent, masking the deletion from internal queries.
- **Did instead:** Built an external anchoring mechanism (`audit.anchor(db, anchorPath)` and `audit.verifyAnchor(db, anchorPath)`). The system periodically or on demand exports `{ seq, head, entries, anchored_at }` to an external, independently permissioned anchor file. When validating, `verifyAnchor()` compares the internal database state with the external anchor, immediately detecting any tail truncation or sequence reduction.
- **How I checked:** Test `test('external audit anchor: anchoring head and detecting tail truncation')`.
