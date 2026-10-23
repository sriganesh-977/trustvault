process.env.BCRYPT_COST = '4';
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const fs = require('fs'), os = require('os'), path = require('path');
const bcrypt = require('bcryptjs');
const { open } = require('../src/db');
const { createApp } = require('../src/app');
const audit = require('../src/audit');

let db, app, blobDir;
const PDF = Buffer.from('%PDF-1.4\nsecret contents of alice\n');
const tokens = {};

function addUser(email, role, pw = 'correct-horse-battery') {
  db.prepare('INSERT INTO users (email,name,password_hash,role,created_at) VALUES (?,?,?,?,?)')
    .run(email, email.split('@')[0], bcrypt.hashSync(pw, 4), role, new Date().toISOString());
}
async function login(email, pw = 'correct-horse-battery') {
  const r = await request(app).post('/api/auth/login').send({ email, password: pw });
  assert.equal(r.status, 200, `login ${email}`);
  return r.body.token;
}
const as = (who) => ({ Authorization: `Bearer ${tokens[who]}` });
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
async function upload(who, buf = PDF, filename = 'plan.pdf', extra = {}) {
  let r = request(app).post('/api/documents').set(as(who)).attach('file', buf, filename);
  for (const [k, v] of Object.entries(extra)) r = r.field(k, v);
  return r;
}
const lastAudit = (action) => db.prepare('SELECT * FROM audit WHERE action=? ORDER BY seq DESC LIMIT 1').get(action);

before(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-'));
  blobDir = path.join(dir, 'blobs');
  db = open(':memory:');
  app = createApp({ db, blobDir });
  for (const [e, r] of [['admin@t.test', 'admin'], ['alice@t.test', 'owner'], ['bob@t.test', 'owner'],
                        ['carol@t.test', 'viewer'], ['dave@t.test', 'viewer']]) addUser(e, r);
  for (const w of ['admin', 'alice', 'bob', 'carol', 'dave']) tokens[w] = await login(`${w}@t.test`);
});

test('every document and admin route rejects unauthenticated callers', async () => {
  const id = (await upload('alice')).body.id;
  const calls = [
    ['get', '/api/documents'], ['get', `/api/documents/${id}`], ['get', `/api/documents/${id}/download`],
    ['patch', `/api/documents/${id}`], ['put', `/api/documents/${id}/content`], ['delete', `/api/documents/${id}`],
    ['get', `/api/documents/${id}/grants`], ['post', `/api/documents/${id}/grants`],
    ['get', '/api/admin/audit'], ['get', '/api/admin/users'], ['get', '/api/admin/documents'], ['post', '/api/documents'],
  ];
  for (const [m, url] of calls) assert.equal((await request(app)[m](url)).status, 401, `${m} ${url}`);
  assert.equal((await request(app).get(`/api/documents/${id}/download`).set(bearer('0'.repeat(64)))).status, 401);
});

test('a user with no grant cannot read, download, edit, replace, delete, or manage grants (all 404)', async () => {
  const id = (await upload('alice')).body.id;
  const probes = [
    request(app).get(`/api/documents/${id}`),
    request(app).get(`/api/documents/${id}/download`),
    request(app).patch(`/api/documents/${id}`).send({ name: 'pwned' }),
    request(app).put(`/api/documents/${id}/content`).attach('file', PDF, 'x.pdf'),
    request(app).delete(`/api/documents/${id}`),
    request(app).get(`/api/documents/${id}/grants`),
    request(app).post(`/api/documents/${id}/grants`).send({ email: 'dave@t.test', level: 'read' }),
  ];
  for (const p of probes) assert.equal((await p.set(as('carol'))).status, 404);
  // Nothing changed:
  assert.equal(db.prepare('SELECT name FROM documents WHERE id=?').get(id).name, 'plan.pdf');
  // Denials were recorded with the real reason:
  const a = lastAudit('document.share');
  assert.equal(a.outcome, 'denied'); assert.equal(a.actor_email, 'carol@t.test');
  assert.equal(JSON.parse(a.detail).reason, 'no_grant');
});

test('"not found" and "not granted" are indistinguishable to the caller', async () => {
  const id = (await upload('alice')).body.id;
  const real = await request(app).get(`/api/documents/${id}`).set(as('carol'));
  const fake = await request(app).get('/api/documents/00000000-0000-4000-8000-000000000000').set(as('carol'));
  assert.equal(real.status, fake.status);
  assert.deepEqual(real.body, fake.body);
});

test('a read grant allows download but not edit, delete, or sharing (403)', async () => {
  const id = (await upload('alice')).body.id;
  await request(app).post(`/api/documents/${id}/grants`).set(as('alice')).send({ email: 'carol@t.test', level: 'read' }).expect(201);
  const dl = await request(app).get(`/api/documents/${id}/download`).set(as('carol'));
  assert.equal(dl.status, 200); assert.deepEqual(dl.body, PDF);
  assert.equal((await request(app).patch(`/api/documents/${id}`).set(as('carol')).send({ name: 'x' })).status, 403);
  assert.equal((await request(app).delete(`/api/documents/${id}`).set(as('carol'))).status, 403);
  assert.equal((await request(app).post(`/api/documents/${id}/grants`).set(as('carol')).send({ email: 'dave@t.test', level: 'read' })).status, 403);
  assert.equal(lastAudit('document.download').outcome, 'allowed');
});

test('an edit grant can edit but still cannot delete or share', async () => {
  const id = (await upload('alice')).body.id;
  await request(app).post(`/api/documents/${id}/grants`).set(as('alice')).send({ email: 'carol@t.test', level: 'edit' }).expect(201);
  await request(app).patch(`/api/documents/${id}`).set(as('carol')).send({ name: 'renamed.pdf' }).expect(200);
  assert.equal((await request(app).delete(`/api/documents/${id}`).set(as('carol'))).status, 403);
  assert.equal((await request(app).post(`/api/documents/${id}/grants`).set(as('carol')).send({ email: 'dave@t.test', level: 'read' })).status, 403);
});

test('revoking a grant works IMMEDIATELY, with the token the user already holds', async () => {
  const id = (await upload('alice')).body.id;
  await request(app).post(`/api/documents/${id}/grants`).set(as('alice')).send({ email: 'dave@t.test', level: 'read' }).expect(201);
  await request(app).get(`/api/documents/${id}/download`).set(as('dave')).expect(200);
  const uid = db.prepare('SELECT id FROM users WHERE email=?').get('dave@t.test').id;
  await request(app).delete(`/api/documents/${id}/grants/${uid}`).set(as('alice')).expect(200);
  assert.equal((await request(app).get(`/api/documents/${id}/download`).set(as('dave'))).status, 404);
  assert.equal((await request(app).get(`/api/documents/${id}`).set(as('dave'))).status, 404);
  assert.ok(lastAudit('permission.revoke'));
});

test('disabling a user kills their existing session immediately', async () => {
  addUser('eve@t.test', 'viewer');
  const t = await login('eve@t.test');
  await request(app).get('/api/me').set(bearer(t)).expect(200);
  const eve = db.prepare('SELECT id FROM users WHERE email=?').get('eve@t.test').id;
  await request(app).patch(`/api/admin/users/${eve}`).set(as('admin')).send({ active: false }).expect(200);
  assert.equal((await request(app).get('/api/me').set(bearer(t))).status, 401);
  assert.equal((await request(app).post('/api/auth/login').send({ email: 'eve@t.test', password: 'correct-horse-battery' })).status, 401);
});

test("an owner cannot grant on, or touch, another owner's document", async () => {
  const bobDoc = (await upload('bob')).body.id;
  assert.equal((await request(app).post(`/api/documents/${bobDoc}/grants`).set(as('alice')).send({ email: 'alice@t.test', level: 'edit' })).status, 404);
  assert.equal((await request(app).get(`/api/documents/${bobDoc}/download`).set(as('alice'))).status, 404);
});

test('role cannot be chosen at registration (mass assignment)', async () => {
  const r = await request(app).post('/api/auth/register').send({ email: 'mallory@t.test', name: 'M', password: 'long-enough-password', role: 'admin' });
  assert.equal(r.status, 201); assert.equal(r.body.role, 'viewer');
  assert.equal(db.prepare('SELECT role FROM users WHERE email=?').get('mallory@t.test').role, 'viewer');
});

test('PATCH cannot reassign ownership or other protected fields', async () => {
  const id = (await upload('alice')).body.id;
  await request(app).patch(`/api/documents/${id}`).set(as('alice')).send({ name: 'ok.pdf', owner_id: 3, sha256: 'x', deleted_at: 'x' }).expect(200);
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(id);
  assert.equal(d.owner_id, db.prepare('SELECT id FROM users WHERE email=?').get('alice@t.test').id);
  assert.equal(d.deleted_at, null);
});

test('only the owner role can upload; viewers and admins cannot', async () => {
  assert.equal((await upload('carol')).status, 403);
  assert.equal((await upload('admin')).status, 403);
});

test('owner can grant named read access during upload, and the grant is enforced', async () => {
  const r = await upload('alice', PDF, 'shared-on-upload.pdf', { grant_email: 'carol@t.test', grant_level: 'read' });
  assert.equal(r.status, 201);
  assert.deepEqual(r.body.grant, { email: 'carol@t.test', level: 'read' });
  const id = r.body.id;
  assert.equal((await request(app).get(`/api/documents/${id}/download`).set(as('carol'))).status, 200);
  assert.equal((await request(app).patch(`/api/documents/${id}`).set(as('carol')).send({ name: 'blocked.pdf' })).status, 403);
  assert.ok(lastAudit('permission.grant'));
});

test('non-admins cannot reach admin endpoints; role check is server-side', async () => {
  for (const w of ['alice', 'carol']) {
    assert.equal((await request(app).get('/api/admin/audit').set(as(w))).status, 403);
    assert.equal((await request(app).patch('/api/admin/users/1').set(as(w)).send({ role: 'admin' })).status, 403);
  }
});

test('an admin sees metadata and the audit log but cannot read document content', async () => {
  const id = (await upload('alice')).body.id;
  assert.equal((await request(app).get(`/api/documents/${id}/download`).set(as('admin'))).status, 404);
  const meta = await request(app).get('/api/admin/documents').set(as('admin')).expect(200);
  assert.ok(meta.body.find((d) => d.id === id));
  assert.equal(meta.body[0].blob_name, undefined);
  assert.equal((await request(app).post(`/api/documents/${id}/grants`).set(as('alice')).send({ email: 'admin@t.test', level: 'read' })).status, 400);
});

test('search never returns, or counts, documents the caller cannot reach', async () => {
  await upload('alice', PDF, 'quarterly-salaries.pdf');
  const mine = await request(app).get('/api/documents?q=salaries').set(as('alice')).expect(200);
  assert.ok(mine.body.length >= 1);
  const theirs = await request(app).get('/api/documents?q=salaries').set(as('dave')).expect(200);
  assert.deepEqual(theirs.body, []);
  const all = await request(app).get('/api/documents').set(as('dave')).expect(200);
  assert.ok(all.body.every((d) => d.name !== 'quarterly-salaries.pdf'));
});

test('search supports category, owner and date filters; LIKE wildcards are escaped', async () => {
  await upload('alice', PDF, 'a.pdf', { category: 'hr' });
  assert.ok((await request(app).get('/api/documents?category=hr').set(as('alice'))).body.length >= 1);
  assert.equal((await request(app).get('/api/documents?category=hr&to=2000-01-01').set(as('alice'))).body.length, 0);
  assert.equal((await request(app).get('/api/documents?q=%25').set(as('alice'))).body.length, 0); // "%" is literal
  assert.ok((await request(app).get('/api/documents?owner=alice').set(as('alice'))).body.length >= 1);
});

test('SQL injection in search and login does not bypass anything', async () => {
  const r = await request(app).get("/api/documents?q=' OR 1=1 --").set(as('dave')).expect(200);
  assert.deepEqual(r.body, []);
  assert.equal((await request(app).post('/api/auth/login').send({ email: "admin@t.test' --", password: 'x' })).status, 401);
});

test('upload validation: bad type, spoofed content, empty file, oversize, hostile filename', async () => {
  assert.equal((await upload('alice', Buffer.from('MZ....'), 'evil.exe')).status, 400);
  assert.equal((await upload('alice', Buffer.from('<script>alert(1)</script>'), 'page.pdf')).status, 400); // wrong magic
  assert.equal((await upload('alice', Buffer.alloc(0), 'empty.pdf')).status, 400);
  assert.equal((await upload('alice', Buffer.concat([PDF, Buffer.alloc(11 * 1024 * 1024)]), 'big.pdf')).status, 413);
  const r = await upload('alice', PDF, '../../etc/passwd.pdf');
  assert.equal(r.status, 201);
  assert.equal(r.body.name, 'passwd.pdf');
  const x = await upload('alice', PDF, '"><img src=x onerror=1>.pdf');
  assert.ok(!/[<>"]/.test(x.body.name));
  // nothing outside blobDir, and blob names are server-generated
  for (const f of fs.readdirSync(blobDir)) assert.match(f, /^[0-9a-f-]{36}$/);
});

test('download is an attachment with nosniff, and the stored blob is not web-reachable', async () => {
  const id = (await upload('alice')).body.id;
  const r = await request(app).get(`/api/documents/${id}/download`).set(as('alice')).expect(200);
  assert.match(r.headers['content-disposition'], /^attachment/);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  const blob = db.prepare('SELECT blob_name FROM documents WHERE id=?').get(id).blob_name;
  assert.equal((await request(app).get(`/${blob}`)).status, 404);
  assert.equal((await request(app).get(`/blobs/${blob}`)).status, 404);
});

test('deleting a document makes it unreachable for everyone, including former grantees', async () => {
  const id = (await upload('alice')).body.id;
  await request(app).post(`/api/documents/${id}/grants`).set(as('alice')).send({ email: 'carol@t.test', level: 'read' });
  await request(app).delete(`/api/documents/${id}`).set(as('alice')).expect(200);
  for (const w of ['alice', 'carol']) assert.equal((await request(app).get(`/api/documents/${id}/download`).set(as(w))).status, 404);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM grants WHERE document_id=?').get(id).n, 0);
});

test('login lockout after repeated failures, and failed attempts are audited', async () => {
  addUser('frank@t.test', 'viewer');
  for (let i = 0; i < 5; i++) assert.equal((await request(app).post('/api/auth/login').send({ email: 'frank@t.test', password: 'wrong-password' })).status, 401);
  assert.equal((await request(app).post('/api/auth/login').send({ email: 'frank@t.test', password: 'correct-horse-battery' })).status, 429);
  assert.equal(lastAudit('login').outcome, 'denied');
});

test('audit: rows cannot be updated or deleted through SQL', () => {
  assert.throws(() => db.prepare("UPDATE audit SET actor_email='x' WHERE seq=1").run(), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM audit WHERE seq=1').run(), /append-only/);
});

test('audit: even with the triggers dropped, tampering or deletion is detected by the hash chain', () => {
  const before = audit.verify(db); assert.equal(before.ok, true); assert.ok(before.entries > 10);
  db.exec('DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete');
  const target = db.prepare("SELECT seq FROM audit WHERE action='document.download' LIMIT 1").get().seq;
  db.prepare("UPDATE audit SET actor_email='nobody@x' WHERE seq=?").run(target);
  const v = audit.verify(db); assert.equal(v.ok, false); assert.equal(v.brokenAt, target);
  db.prepare("UPDATE audit SET actor_email='carol@t.test' WHERE seq=?").run(target);   // undo to test deletion next
  const deletedRow = db.prepare('SELECT * FROM audit WHERE seq=?').get(target + 1);
  db.prepare('DELETE FROM audit WHERE seq=?').run(target + 1);
  assert.equal(audit.verify(db).ok, false);
  // Restore row and triggers so audit chain remains valid for following tests
  if (deletedRow) {
    db.prepare(`INSERT INTO audit (seq,ts,actor_id,actor_email,action,outcome,document_id,detail,ip,prev_hash,hash)
      VALUES (@seq,@ts,@actor_id,@actor_email,@action,@outcome,@document_id,@detail,@ip,@prev_hash,@hash)`).run(deletedRow);
  }
  db.exec(`CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
           CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;`);
  assert.equal(audit.verify(db).ok, true);
});

test('the admin audit endpoint reports chain status', async () => {
  const r = await request(app).get('/api/admin/audit/verify').set(as('admin')).expect(200);
  assert.equal(typeof r.body.ok, 'boolean');
  const alerts = await request(app).get('/api/admin/alerts').set(as('admin')).expect(200);
  assert.ok(Array.isArray(alerts.body.repeated_denials));
});

test('document versioning: uploading, replacing content, listing versions, downloading historical versions and rollback', async () => {
  const v1Buf = Buffer.from('%PDF-1.4\nversion 1 content\n');
  const v2Buf = Buffer.from('%PDF-1.4\nversion 2 updated content\n');
  const up = await upload('alice', v1Buf, 'doc.pdf');
  const id = up.body.id;

  // List versions: initially version 1
  const vList1 = await request(app).get(`/api/documents/${id}/versions`).set(as('alice')).expect(200);
  assert.equal(vList1.body.length, 1);
  assert.equal(vList1.body[0].version_number, 1);

  // Replace content with v2
  await request(app).put(`/api/documents/${id}/content`).set(as('alice')).attach('file', v2Buf, 'doc.pdf').expect(200);

  // List versions: now has v1 and v2
  const vList2 = await request(app).get(`/api/documents/${id}/versions`).set(as('alice')).expect(200);
  assert.equal(vList2.body.length, 2);
  assert.equal(vList2.body[0].version_number, 2);
  assert.equal(vList2.body[1].version_number, 1);

  // Active download gets v2
  const dlActive = await request(app).get(`/api/documents/${id}/download`).set(as('alice')).expect(200);
  assert.deepEqual(dlActive.body, v2Buf);

  // Download historical v1
  const dlV1 = await request(app).get(`/api/documents/${id}/versions/1/download`).set(as('alice')).expect(200);
  assert.deepEqual(dlV1.body, v1Buf);

  // Rollback to v1 creates v3 with v1 content
  const rb = await request(app).post(`/api/documents/${id}/rollback/1`).set(as('alice')).expect(200);
  assert.equal(rb.body.version, 3);
  assert.equal(rb.body.restored_from, 1);

  const dlAfterRb = await request(app).get(`/api/documents/${id}/download`).set(as('alice')).expect(200);
  assert.deepEqual(dlAfterRb.body, v1Buf);

  // Read grant holder can view/download versions, but cannot rollback
  await request(app).post(`/api/documents/${id}/grants`).set(as('alice')).send({ email: 'carol@t.test', level: 'read' });
  const carolList = await request(app).get(`/api/documents/${id}/versions`).set(as('carol')).expect(200);
  assert.equal(carolList.body.length, 3);
  assert.equal((await request(app).post(`/api/documents/${id}/rollback/2`).set(as('carol'))).status, 403);
});

test('concurrency: simultaneous parallel audit writes preserve hash chain integrity', async () => {
  const ops = [];
  for (let i = 0; i < 30; i++) {
    ops.push(request(app).get('/api/documents?q=concurrency_test').set(as('alice')));
  }
  const results = await Promise.all(ops);
  for (const r of results) {
    assert.equal(r.status, 200);
  }
  const v = audit.verify(db);
  assert.equal(v.ok, true, 'Audit chain integrity maintained under concurrent writes');
  assert.equal(v.brokenAt, null);
});

test('external audit anchor: anchoring head and detecting tail truncation', async () => {
  const anchorRes = await request(app).post('/api/admin/audit/anchor').set(as('admin')).expect(201);
  assert.ok(anchorRes.body.head);
  assert.ok(anchorRes.body.seq > 0);

  const check = await request(app).get('/api/admin/audit/anchor').set(as('admin')).expect(200);
  assert.equal(check.body.anchored, true);
  assert.equal(check.body.ok, true);

  // Simulate an attacker dropping triggers and truncating newest rows
  db.exec('DROP TRIGGER IF EXISTS audit_no_delete');
  const lastSeq = db.prepare('SELECT seq FROM audit ORDER BY seq DESC LIMIT 1').get().seq;
  const savedRow = db.prepare('SELECT * FROM audit WHERE seq=?').get(lastSeq);
  db.prepare('DELETE FROM audit WHERE seq=?').run(lastSeq);

  const checkTampered = await request(app).get('/api/admin/audit/anchor').set(as('admin')).expect(200);
  assert.equal(checkTampered.body.anchored, true);
  assert.equal(checkTampered.body.ok, false);
  assert.equal(checkTampered.body.reason, 'tail_truncation_detected');

  // Restore deleted row and trigger
  db.prepare(`INSERT INTO audit (seq,ts,actor_id,actor_email,action,outcome,document_id,detail,ip,prev_hash,hash)
    VALUES (@seq,@ts,@actor_id,@actor_email,@action,@outcome,@document_id,@detail,@ip,@prev_hash,@hash)`).run(savedRow);
  db.exec("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;");
});

test('session security: httpOnly cookie auth and CSRF protection', async () => {
  const loginRes = await request(app).post('/api/auth/login').send({ email: 'alice@t.test', password: 'correct-horse-battery' }).expect(200);
  const cookie = loginRes.headers['set-cookie']?.find(c => c.startsWith('tv_session='));
  assert.ok(cookie, 'Set-Cookie header present');
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Strict/i);

  const csrf = loginRes.body.csrfToken;
  assert.ok(csrf, 'CSRF token returned');

  // Authenticate using cookie for GET request (safe method) - should succeed
  const me = await request(app).get('/api/me').set('Cookie', cookie).expect(200);
  assert.equal(me.body.email, 'alice@t.test');

  // Mutating request using cookie WITHOUT CSRF token - should be rejected with 403
  const patchWithoutCsrf = await request(app).patch('/api/documents/nonexistent')
    .set('Cookie', cookie)
    .send({ name: 'test' });
  assert.equal(patchWithoutCsrf.status, 403);
  assert.match(patchWithoutCsrf.body.error, /CSRF/i);

  // Mutating request using cookie WITH valid CSRF token header - passes CSRF gate (returns 404 for nonexistent doc)
  const patchWithCsrf = await request(app).patch('/api/documents/nonexistent')
    .set('Cookie', cookie)
    .set('X-CSRF-Token', csrf)
    .send({ name: 'test' });
  assert.equal(patchWithCsrf.status, 404);

  // Mutating request using cookie WITH X-Requested-With header - passes CSRF gate
  const patchWithXHR = await request(app).patch('/api/documents/nonexistent')
    .set('Cookie', cookie)
    .set('X-Requested-With', 'XMLHttpRequest')
    .send({ name: 'test' });
  assert.equal(patchWithXHR.status, 404);
});
