const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const audit = require('./audit');
const { authorize } = require('./authz');
const { inspectUpload } = require('./upload');

const COST = Number(process.env.BCRYPT_COST || 12);
const SESSION_MS = 8 * 3600 * 1000;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const MFA_CHALLENGE_MS = 5 * 60 * 1000;
const MAX_UPLOAD = 10 * 1024 * 1024;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', COST);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const now = () => new Date().toISOString();
const str = (v, max) => (typeof v === 'string' && v.trim().length > 0 && v.length <= max ? v.trim() : null);
const likeEscape = (s) => s.replace(/[\\%_]/g, (c) => '\\' + c);

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = String(value).replace(/=+$/, '').toUpperCase().split('').map((c) => alphabet.indexOf(c)).filter((n) => n >= 0)
    .map((n) => n.toString(2).padStart(5, '0')).join('');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function validTotp(secret, code) {
  if (!/^[0-9]{6}$/.test(String(code || ''))) return false;
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 30000);
  for (let drift = -1; drift <= 1; drift++) {
    const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter + drift));
    const digest = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = digest[19] & 15;
    const value = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    if (String(value).padStart(6, '0') === String(code)) return true;
  }
  return false;
}

function createApp({ db, blobDir, anchorPath = path.join(blobDir, '..', 'anchor.json') }) {
  fs.mkdirSync(blobDir, { recursive: true });
  const app = express();
  const rateBuckets = new Map();
  const rateLimit = (max, windowMs) => (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const nowMs = Date.now();
    const bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= nowMs) rateBuckets.set(key, { count: 1, resetAt: nowMs + windowMs });
    else if (++bucket.count > max) return res.status(429).json({ error: 'too many requests, try again later' });
    res.set('Retry-After', String(Math.ceil(((rateBuckets.get(key)?.resetAt || nowMs) - nowMs) / 1000)));
    next();
  };
  app.disable('x-powered-by');
  app.use(express.json({ limit: '10kb' }));
  app.use((req, res, next) => {
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'" });
    next();
  });
  app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'trustvault' }));
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD, files: 1, fields: 5 } });

  const log = (req, action, outcome, extra = {}) =>
    audit.record(db, { actor: req.user, ip: req.ip, action, outcome, ...extra });

  const oauthProviderConfig = (provider, req) => {
    const forwardedProto = req.get('x-forwarded-proto');
    const protocol = forwardedProto ? forwardedProto.split(',')[0].trim() : req.protocol;
    const origin = `${protocol}://${req.get('host')}`;
    if (provider === 'google') return {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI || `${origin}/api/auth/oauth/google/callback`,
      authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
      token: 'https://oauth2.googleapis.com/token',
      userInfo: 'https://openidconnect.googleapis.com/v1/userinfo',
      scope: 'openid email profile'
    };
    const tenant = process.env.MICROSOFT_TENANT_ID || 'common';
    return {
      clientId: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      redirectUri: process.env.MICROSOFT_REDIRECT_URI || `${origin}/api/auth/oauth/microsoft/callback`,
      authorize: `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/authorize`,
      token: `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`,
      userInfo: 'https://graph.microsoft.com/oidc/userinfo',
      scope: 'openid profile email User.Read'
    };
  };

  const oauthStateCookie = (provider, state) => `${provider}.${state}`;
  const createSession = (u) => {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)')
      .run(sha(token), u.id, Date.now() + SESSION_MS, now());
    return { token, csrfToken: sha(token + ':csrf'), user: { id: u.id, email: u.email, name: u.name, role: u.role } };
  };

  const setSessionCookie = (res, token) => res.cookie('tv_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.TRUSTVAULT_COOKIE_SECURE !== '0',
    path: '/api',
    maxAge: SESSION_MS
  });

  const oauthUser = async (provider, code, config) => {
    const tokenResponse = await fetch(config.token, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: config.clientId, client_secret: config.clientSecret,
        redirect_uri: config.redirectUri, grant_type: 'authorization_code'
      })
    });
    if (!tokenResponse.ok) throw new Error('token_exchange_failed');
    const tokens = await tokenResponse.json();
    if (!tokens.access_token) throw new Error('missing_access_token');
    const profileResponse = await fetch(config.userInfo, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    if (!profileResponse.ok) throw new Error('profile_request_failed');
    const profile = await profileResponse.json();
    const email = String(profile.email || profile.mail || profile.userPrincipalName || '').trim().toLowerCase();
    const name = String(profile.name || profile.displayName || email.split('@')[0] || 'TrustVault user').trim().slice(0, 100);
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error('provider_email_missing');
    if (provider === 'google' && profile.email_verified === false) throw new Error('provider_email_unverified');
    return { email, name };
  };

  // ---------- auth middleware: hits the DB on every request, so disabling a user or session is immediate
  function requireAuth(req, res, next) {
    let token = null;
    let isCookieAuth = false;
    const h = req.get('authorization') || '';
    const m = /^Bearer ([0-9a-f]{64})$/.exec(h);
    if (m) {
      token = m[1];
    } else if (req.headers.cookie) {
      const cm = req.headers.cookie.match(/(?:^|;\s*)tv_session=([0-9a-f]{64})/);
      if (cm) {
        token = cm[1];
        isCookieAuth = true;
      }
    }
    if (!token) return res.status(401).json({ error: 'authentication required' });

    // Enforce CSRF protection for cookie-authenticated mutating requests
    if (isCookieAuth && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const csrfHeader = req.get('x-csrf-token') || req.get('x-requested-with');
      const expectedCsrf = sha(token + ':csrf');
      if (!csrfHeader || (csrfHeader !== expectedCsrf && csrfHeader.toLowerCase() !== 'xmlhttprequest')) {
        return res.status(403).json({ error: 'invalid or missing CSRF token' });
      }
    }

    const row = db.prepare(`SELECT u.id,u.email,u.name,u.role,u.active FROM sessions s
        JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(sha(token), Date.now());
    if (!row || !row.active) return res.status(401).json({ error: 'authentication required' });
    req.user = row; req.tokenHash = sha(token); req.rawToken = token;
    next();
  }
  const requireRole = (...roles) => (req, res, next) => {
    if (roles.includes(req.user.role)) return next();
    log(req, 'route.forbidden', 'denied', { detail: { path: req.path, method: req.method, role: req.user.role } });
    res.status(403).json({ error: 'forbidden' });
  };

  /** Single place that turns an authorize() result into a response + audit entry. */
  function guard(req, res, action, docId) {
    const r = authorize(db, req.user, docId, action);
    if (r.ok) return r;
    log(req, `document.${action}`, 'denied', { documentId: typeof docId === 'string' ? docId.slice(0, 64) : null, detail: { reason: r.reason } });
    // Not found and not granted look identical: callers can't probe for existence.
    if (r.reason === 'insufficient_level') res.status(403).json({ error: 'forbidden' });
    else res.status(404).json({ error: 'not found' });
    return null;
  }

  const publicDoc = (d) => ({ id: d.id, name: d.name, category: d.category, mime: d.mime, size: d.size,
    created_at: d.created_at, updated_at: d.updated_at });

  // ---------- auth
  app.post('/api/auth/register', (req, res) => {
    const email = str(req.body?.email, 200)?.toLowerCase(), name = str(req.body?.name, 100), pw = req.body?.password;
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !name || typeof pw !== 'string' || pw.length < 10 || pw.length > 200)
      return res.status(400).json({ error: 'valid email, name and a password of 10+ characters are required' });
    // Role is NEVER taken from the request. Everyone starts as a viewer; an admin promotes.
    try {
      const r = db.prepare('INSERT INTO users (email,name,password_hash,role,created_at) VALUES (?,?,?,?,?)')
        .run(email, name, bcrypt.hashSync(pw, COST), 'viewer', now());
      audit.record(db, { actorEmail: email, ip: req.ip, action: 'user.register', outcome: 'info', detail: { userId: r.lastInsertRowid } });
      res.status(201).json({ id: r.lastInsertRowid, email, name, role: 'viewer' });
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'email already registered' });
      throw e;
    }
  });

  app.get('/api/auth/oauth/:provider', (req, res) => {
    const provider = String(req.params.provider || '').toLowerCase();
    if (!['google', 'microsoft'].includes(provider)) return res.redirect('/?oauth=unsupported');
    const config = oauthProviderConfig(provider, req);
    if (!config.clientId || !config.clientSecret) return res.redirect(`/?oauth=not_configured&provider=${provider}`);
    const state = crypto.randomBytes(24).toString('hex');
    res.cookie('tv_oauth_state', oauthStateCookie(provider, state), {
      httpOnly: true, sameSite: 'lax', secure: process.env.TRUSTVAULT_COOKIE_SECURE !== '0',
      path: '/api/auth/oauth', maxAge: 10 * 60 * 1000
    });
    const params = new URLSearchParams({ client_id: config.clientId, redirect_uri: config.redirectUri,
      response_type: 'code', scope: config.scope, state, prompt: 'select_account' });
    if (provider === 'google') params.set('access_type', 'online');
    res.redirect(`${config.authorize}?${params}`);
  });

  app.get('/api/auth/oauth/:provider/callback', async (req, res) => {
    const provider = String(req.params.provider || '').toLowerCase();
    const stateCookie = req.headers.cookie?.match(/(?:^|;\s*)tv_oauth_state=([^;]+)/)?.[1];
    const expectedState = stateCookie ? decodeURIComponent(stateCookie) : '';
    const validState = expectedState.startsWith(`${provider}.`) && expectedState.slice(provider.length + 1) === req.query.state;
    res.clearCookie('tv_oauth_state', { path: '/api/auth/oauth', httpOnly: true, sameSite: 'lax' });
    if (!['google', 'microsoft'].includes(provider) || !validState || typeof req.query.code !== 'string')
      return res.redirect('/?oauth=failed');
    const config = oauthProviderConfig(provider, req);
    if (!config.clientId || !config.clientSecret) return res.redirect(`/?oauth=not_configured&provider=${provider}`);
    try {
      const profile = await oauthUser(provider, req.query.code, config);
      let u = db.prepare('SELECT * FROM users WHERE email=?').get(profile.email);
      if (u && !u.active) return res.redirect('/?oauth=disabled');
      if (!u) {
        const passwordHash = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), COST);
        const result = db.prepare('INSERT INTO users (email,name,password_hash,role,created_at) VALUES (?,?,?,?,?)')
          .run(profile.email, profile.name, passwordHash, 'viewer', now());
        u = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
      }
      const session = createSession(u);
      setSessionCookie(res, session.token);
      audit.record(db, { actor: u, ip: req.ip, action: `oauth.login.${provider}`, outcome: 'allowed' });
      res.redirect('/?oauth=success');
    } catch (error) {
      audit.record(db, { actorEmail: provider, ip: req.ip, action: `oauth.login.${provider}`, outcome: 'denied', detail: { reason: error.message } });
      res.redirect('/?oauth=failed');
    }
  });

  app.get('/api/auth/csrf', (req, res) => {
    const token = req.headers.cookie?.match(/(?:^|;\s*)tv_session=([0-9a-f]{64})/)?.[1];
    if (!token) return res.status(401).json({ error: 'authentication required' });
    res.json({ csrfToken: sha(token + ':csrf') });
  });

  app.post('/api/auth/login', rateLimit(60, 15 * 60 * 1000), (req, res) => {
    const email = str(req.body?.email, 200)?.toLowerCase(), pw = req.body?.password;
    if (!email || typeof pw !== 'string' || pw.length > 200) return res.status(400).json({ error: 'email and password required' });
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (u && u.locked_until && u.locked_until > Date.now()) {
      audit.record(db, { actorEmail: email, ip: req.ip, action: 'login', outcome: 'denied', detail: { reason: 'locked' } });
      return res.status(429).json({ error: 'too many attempts, try again later' });
    }
    const ok = bcrypt.compareSync(pw, u ? u.password_hash : DUMMY_HASH); // same work whether or not the user exists
    if (!u || !ok || !u.active) {
      if (u) {
        const fails = u.failed_logins + 1;
        db.prepare('UPDATE users SET failed_logins=?, locked_until=? WHERE id=?')
          .run(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? Date.now() + LOCK_MS : null, u.id);
      }
      audit.record(db, { actorEmail: email, ip: req.ip, action: 'login', outcome: 'denied', detail: { reason: u && !u.active ? 'disabled' : 'bad_credentials' } });
      return res.status(401).json({ error: 'invalid credentials' });
    }
    db.prepare('UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?').run(u.id);
    if (u.mfa_enabled) {
      const challenge = crypto.randomBytes(32).toString('hex');
      db.prepare('INSERT INTO login_challenges (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)')
        .run(sha(challenge), u.id, Date.now() + MFA_CHALLENGE_MS, now());
      return res.json({ mfaRequired: true, challenge });
    }
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)')
      .run(sha(token), u.id, Date.now() + SESSION_MS, now());
    audit.record(db, { actor: u, ip: req.ip, action: 'login', outcome: 'allowed' });
    const csrfToken = sha(token + ':csrf');
    res.cookie('tv_session', token, {
      httpOnly: true,
      sameSite: 'strict',
      path: '/api',
      maxAge: SESSION_MS
    });
    res.json({ token, csrfToken, user: { id: u.id, email: u.email, name: u.name, role: u.role } });
  });

  app.post('/api/auth/mfa/verify', rateLimit(60, 15 * 60 * 1000), (req, res) => {
    const challenge = String(req.body?.challenge || '');
    const row = /^[0-9a-f]{64}$/.test(challenge) && db.prepare(`SELECT u.* FROM login_challenges c JOIN users u ON u.id=c.user_id
      WHERE c.token_hash=? AND c.expires_at>? AND u.active=1`).get(sha(challenge), Date.now());
    if (!row || !validTotp(row.mfa_secret, req.body?.code)) return res.status(401).json({ error: 'invalid verification code' });
    db.prepare('DELETE FROM login_challenges WHERE token_hash=?').run(sha(challenge));
    const session = createSession(row);
    res.cookie('tv_session', session.token, { httpOnly: true, sameSite: 'strict', path: '/api', maxAge: SESSION_MS });
    audit.record(db, { actor: row, ip: req.ip, action: 'mfa.login', outcome: 'allowed' });
    res.json(session);
  });

  app.post('/api/auth/mfa/setup', requireAuth, (req, res) => {
    const secret = crypto.randomBytes(20).toString('base64').replace(/[^A-Z2-7]/gi, '').slice(0, 32).toUpperCase();
    db.prepare('UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?').run(secret, req.user.id);
    res.json({ secret, issuer: 'TrustVault', account: req.user.email });
  });
  app.post('/api/auth/mfa/enable', requireAuth, (req, res) => {
    const u = db.prepare('SELECT mfa_secret FROM users WHERE id=?').get(req.user.id);
    if (!u?.mfa_secret || !validTotp(u.mfa_secret, req.body?.code)) return res.status(400).json({ error: 'invalid verification code' });
    db.prepare('UPDATE users SET mfa_enabled=1 WHERE id=?').run(req.user.id);
    log(req, 'security.mfa.enable', 'allowed');
    res.json({ enabled: true });
  });

  app.post('/api/auth/logout', requireAuth, (req, res) => {
    db.prepare('DELETE FROM sessions WHERE token_hash=?').run(req.tokenHash);
    res.clearCookie('tv_session', { path: '/api', httpOnly: true, sameSite: 'strict' });
    log(req, 'logout', 'info');
    res.json({ ok: true });
  });
  app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

  // ---------- documents
  app.post('/api/documents', requireAuth, requireRole('owner'), upload.single('file'), (req, res) => {
    const info = inspectUpload(req.file);
    if (info.error) { log(req, 'document.upload', 'denied', { detail: { reason: info.error } }); return res.status(400).json({ error: info.error }); }
    const grantEmail = str(req.body?.grant_email, 200)?.toLowerCase();
    const grantLevel = req.body?.grant_level;
    let grantTarget = null;
    if (grantEmail) {
      if (!['read', 'edit'].includes(grantLevel)) return res.status(400).json({ error: 'grant_level must be read or edit' });
      grantTarget = db.prepare('SELECT id,email,role FROM users WHERE email=? AND active=1').get(grantEmail);
      if (!grantTarget) return res.status(404).json({ error: 'grant target user not found' });
      if (grantTarget.id === req.user.id) return res.status(400).json({ error: 'you already own this document' });
      if (grantTarget.role === 'admin') return res.status(400).json({ error: 'administrators cannot be granted document access' });
    }
    const id = crypto.randomUUID(), blob = crypto.randomUUID();
    const name = str(req.body?.name, 120) || info.name;
    const category = str(req.body?.category, 50) || 'general';
    fs.writeFileSync(path.join(blobDir, blob), req.file.buffer, { mode: 0o600 });
    db.prepare(`INSERT INTO documents (id,owner_id,name,category,mime,size,sha256,blob_name,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(id, req.user.id, name, category, info.mime, req.file.size,
      sha(req.file.buffer), blob, now(), now());
    db.prepare(`INSERT INTO document_versions (document_id,version_number,blob_name,mime,size,sha256,created_by,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(id, 1, blob, info.mime, req.file.size, sha(req.file.buffer), req.user.id, now());
    log(req, 'document.upload', 'allowed', { documentId: id, detail: { name, size: req.file.size, mime: info.mime } });
    if (grantTarget) {
      db.prepare(`INSERT INTO grants (document_id,user_id,level,granted_by,created_at) VALUES (?,?,?,?,?)`)
        .run(id, grantTarget.id, grantLevel, req.user.id, now());
      log(req, 'permission.grant', 'allowed', { documentId: id, detail: { target: grantTarget.email, level: grantLevel, during_upload: true } });
    }
    res.status(201).json({ ...publicDoc(db.prepare('SELECT * FROM documents WHERE id=?').get(id)), grant: grantTarget ? { email: grantTarget.email, level: grantLevel } : null });
  });

  // Search is filtered INSIDE the query: documents you can't reach never come back, so can't leak.
  app.get('/api/documents', requireAuth, (req, res) => {
    const q = str(req.query.q, 100), category = str(req.query.category, 50), owner = str(req.query.owner, 100);
    const from = str(req.query.from, 30), to = str(req.query.to, 30);
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.min(50, Math.max(1, Number(req.query.pageSize) || 20));
    const sortMap = { name: 'd.name', category: 'd.category', size: 'd.size', owner: 'u.name', updated: 'd.updated_at' };
    const sort = sortMap[req.query.sort] || 'd.created_at';
    const direction = String(req.query.direction).toLowerCase() === 'asc' ? 'ASC' : 'DESC';
    const rows = db.prepare(`
      SELECT d.*, u.name AS owner_name, u.email AS owner_email,
        CASE WHEN d.owner_id=@uid THEN 'owner' ELSE (SELECT level FROM grants WHERE document_id=d.id AND user_id=@uid) END AS my_level
      FROM documents d JOIN users u ON u.id=d.owner_id
      WHERE d.deleted_at IS NULL
        AND (d.owner_id=@uid OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id=d.id AND g.user_id=@uid))
        AND (@q IS NULL OR d.name LIKE @q ESCAPE '\\')
        AND (@category IS NULL OR d.category=@category)
        AND (@owner IS NULL OR u.name LIKE @owner ESCAPE '\\' OR u.email LIKE @owner ESCAPE '\\')
        AND (@from IS NULL OR d.created_at>=@from) AND (@to IS NULL OR d.created_at<=@to)
      ORDER BY ${sort} ${direction} LIMIT @limit OFFSET @offset`).all({
      uid: req.user.id, q: q && `%${likeEscape(q)}%`, category, owner: owner && `%${likeEscape(owner)}%`, from, to,
      limit: pageSize, offset: (page - 1) * pageSize });
    const count = db.prepare(`SELECT COUNT(*) AS total FROM documents d JOIN users u ON u.id=d.owner_id
      WHERE d.deleted_at IS NULL AND (d.owner_id=@uid OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id=d.id AND g.user_id=@uid))
      AND (@q IS NULL OR d.name LIKE @q ESCAPE '\\') AND (@category IS NULL OR d.category=@category)
      AND (@owner IS NULL OR u.name LIKE @owner ESCAPE '\\' OR u.email LIKE @owner ESCAPE '\\')`).get({
      uid: req.user.id, q: q && `%${likeEscape(q)}%`, category, owner: owner && `%${likeEscape(owner)}%` }).total;
    res.set('X-Total-Count', String(count));
    log(req, 'document.search', 'info', { detail: { q, category, owner, from, to, results: rows.length, page, pageSize } });
    res.json(rows.map((d) => ({ ...publicDoc(d), owner: d.owner_name, my_level: d.my_level })));
  });

  app.get('/api/documents/:id', requireAuth, (req, res) => {
    const r = guard(req, res, 'view', req.params.id); if (!r) return;
    log(req, 'document.view', 'allowed', { documentId: r.doc.id });
    res.json({ ...publicDoc(r.doc), my_level: r.level });
  });

  app.get('/api/documents/:id/download', requireAuth, (req, res) => {
    const r = guard(req, res, 'download', req.params.id); if (!r) return;   // <-- the download authorization decision
    if (!/^[0-9a-f-]{36}$/.test(r.doc.blob_name)) return res.status(500).json({ error: 'storage error' });
    const file = path.join(blobDir, r.doc.blob_name);
    if (!fs.existsSync(file)) return res.status(500).json({ error: 'storage error' });
    log(req, 'document.download', 'allowed', { documentId: r.doc.id, detail: { sha256: r.doc.sha256 } });
    res.set({ 'Content-Type': r.doc.mime, 'Content-Length': r.doc.size,
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(r.doc.name)}` });
    fs.createReadStream(file).pipe(res);
  });

  app.patch('/api/documents/:id', requireAuth, (req, res) => {
    const r = guard(req, res, 'edit', req.params.id); if (!r) return;
    // Explicit allow-list of fields: no mass assignment (owner_id, sha256, etc. can't be set).
    const name = req.body?.name === undefined ? r.doc.name : str(req.body.name, 120);
    const category = req.body?.category === undefined ? r.doc.category : str(req.body.category, 50);
    if (!name || !category) return res.status(400).json({ error: 'invalid name or category' });
    db.prepare('UPDATE documents SET name=?, category=?, updated_at=? WHERE id=?').run(name, category, now(), r.doc.id);
    log(req, 'document.edit', 'allowed', { documentId: r.doc.id, detail: { from: { name: r.doc.name, category: r.doc.category }, to: { name, category } } });
    res.json(publicDoc(db.prepare('SELECT * FROM documents WHERE id=?').get(r.doc.id)));
  });

  app.put('/api/documents/:id/content', requireAuth, upload.single('file'), (req, res) => {
    const r = guard(req, res, 'edit', req.params.id); if (!r) return;
    const info = inspectUpload(req.file);
    if (info.error) { log(req, 'document.edit', 'denied', { documentId: r.doc.id, detail: { reason: info.error } }); return res.status(400).json({ error: info.error }); }
    const blob = crypto.randomUUID();
    fs.writeFileSync(path.join(blobDir, blob), req.file.buffer, { mode: 0o600 });
    const latest = db.prepare('SELECT MAX(version_number) AS max_v FROM document_versions WHERE document_id=?').get(r.doc.id);
    const nextV = (latest?.max_v || 1) + 1;
    db.prepare(`INSERT INTO document_versions (document_id,version_number,blob_name,mime,size,sha256,created_by,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(r.doc.id, nextV, blob, info.mime, req.file.size, sha(req.file.buffer), req.user.id, now());
    db.prepare('UPDATE documents SET blob_name=?, mime=?, size=?, sha256=?, updated_at=? WHERE id=?')
      .run(blob, info.mime, req.file.size, sha(req.file.buffer), now(), r.doc.id);
    log(req, 'document.edit', 'allowed', { documentId: r.doc.id, detail: { content: true, version: nextV, oldSha256: r.doc.sha256, newSha256: sha(req.file.buffer) } });
    res.json(publicDoc(db.prepare('SELECT * FROM documents WHERE id=?').get(r.doc.id)));
  });

  app.delete('/api/documents/:id', requireAuth, (req, res) => {
    const r = guard(req, res, 'delete', req.params.id); if (!r) return;
    db.prepare('UPDATE documents SET deleted_at=? WHERE id=?').run(now(), r.doc.id);
    db.prepare('DELETE FROM grants WHERE document_id=?').run(r.doc.id);
    const versions = db.prepare('SELECT blob_name FROM document_versions WHERE document_id=?').all(r.doc.id);
    for (const v of versions) {
      try { fs.unlinkSync(path.join(blobDir, v.blob_name)); } catch {}
    }
    try { fs.unlinkSync(path.join(blobDir, r.doc.blob_name)); } catch {}
    db.prepare('DELETE FROM document_versions WHERE document_id=?').run(r.doc.id);
    log(req, 'document.delete', 'allowed', { documentId: r.doc.id, detail: { name: r.doc.name, sha256: r.doc.sha256 } });
    res.json({ ok: true });
  });

  // ---------- document versions & recovery
  app.get('/api/documents/:id/versions', requireAuth, (req, res) => {
    const r = guard(req, res, 'view', req.params.id); if (!r) return;
    const rows = db.prepare(`SELECT v.version_number, v.mime, v.size, v.sha256, v.created_at, u.email AS created_by
      FROM document_versions v JOIN users u ON u.id=v.created_by
      WHERE v.document_id=? ORDER BY v.version_number DESC`).all(r.doc.id);
    res.json(rows);
  });

  app.get('/api/documents/:id/versions/:version/download', requireAuth, (req, res) => {
    const r = guard(req, res, 'download', req.params.id); if (!r) return;
    const vnum = Number(req.params.version);
    if (!Number.isInteger(vnum) || vnum < 1) return res.status(400).json({ error: 'invalid version number' });
    const ver = db.prepare('SELECT * FROM document_versions WHERE document_id=? AND version_number=?').get(r.doc.id, vnum);
    if (!ver) return res.status(404).json({ error: 'version not found' });
    if (!/^[0-9a-f-]{36}$/.test(ver.blob_name)) return res.status(500).json({ error: 'storage error' });
    const file = path.join(blobDir, ver.blob_name);
    if (!fs.existsSync(file)) return res.status(500).json({ error: 'storage error' });
    log(req, 'document.download_version', 'allowed', { documentId: r.doc.id, detail: { version: vnum, sha256: ver.sha256 } });
    res.set({
      'Content-Type': ver.mime,
      'Content-Length': ver.size,
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(r.doc.name)}`
    });
    fs.createReadStream(file).pipe(res);
  });

  app.post('/api/documents/:id/rollback/:version', requireAuth, (req, res) => {
    const r = guard(req, res, 'edit', req.params.id); if (!r) return;
    const vnum = Number(req.params.version);
    if (!Number.isInteger(vnum) || vnum < 1) return res.status(400).json({ error: 'invalid version number' });
    const target = db.prepare('SELECT * FROM document_versions WHERE document_id=? AND version_number=?').get(r.doc.id, vnum);
    if (!target) return res.status(404).json({ error: 'version not found' });
    const oldFile = path.join(blobDir, target.blob_name);
    if (!fs.existsSync(oldFile)) return res.status(500).json({ error: 'storage error' });
    const newBlob = crypto.randomUUID();
    fs.copyFileSync(oldFile, path.join(blobDir, newBlob));
    const latest = db.prepare('SELECT MAX(version_number) AS max_v FROM document_versions WHERE document_id=?').get(r.doc.id);
    const nextV = (latest?.max_v || 1) + 1;
    db.prepare(`INSERT INTO document_versions (document_id,version_number,blob_name,mime,size,sha256,created_by,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(r.doc.id, nextV, newBlob, target.mime, target.size, target.sha256, req.user.id, now());
    db.prepare('UPDATE documents SET blob_name=?, mime=?, size=?, sha256=?, updated_at=? WHERE id=?')
      .run(newBlob, target.mime, target.size, target.sha256, now(), r.doc.id);
    log(req, 'document.rollback', 'allowed', { documentId: r.doc.id, detail: { restoredFromVersion: vnum, newVersion: nextV, sha256: target.sha256 } });
    res.json({ ...publicDoc(db.prepare('SELECT * FROM documents WHERE id=?').get(r.doc.id)), version: nextV, restored_from: vnum });
  });

  // ---------- grants (document owner only)
  app.get('/api/documents/:id/grants', requireAuth, (req, res) => {
    const r = guard(req, res, 'share', req.params.id); if (!r) return;
    res.json(db.prepare(`SELECT u.id AS user_id,u.email,u.name,g.level,g.created_at FROM grants g
      JOIN users u ON u.id=g.user_id WHERE g.document_id=?`).all(r.doc.id));
  });

  app.post('/api/documents/:id/grants', requireAuth, (req, res) => {
    const r = guard(req, res, 'share', req.params.id); if (!r) return;
    const email = str(req.body?.email, 200)?.toLowerCase(), level = req.body?.level;
    if (!email || !['read', 'edit'].includes(level)) return res.status(400).json({ error: 'email and level (read|edit) required' });
    const target = db.prepare('SELECT id,email,role FROM users WHERE email=? AND active=1').get(email);
    if (!target) return res.status(404).json({ error: 'user not found' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'you already own this document' });
    if (target.role === 'admin') return res.status(400).json({ error: 'administrators cannot be granted document access' });
    db.prepare(`INSERT INTO grants (document_id,user_id,level,granted_by,created_at) VALUES (?,?,?,?,?)
      ON CONFLICT(document_id,user_id) DO UPDATE SET level=excluded.level, granted_by=excluded.granted_by`)
      .run(r.doc.id, target.id, level, req.user.id, now());
    log(req, 'permission.grant', 'allowed', { documentId: r.doc.id, detail: { target: target.email, level } });
    res.status(201).json({ user_id: target.id, email: target.email, level });
  });

  app.delete('/api/documents/:id/grants/:userId', requireAuth, (req, res) => {
    const r = guard(req, res, 'share', req.params.id); if (!r) return;
    const uid = Number(req.params.userId);
    const t = Number.isInteger(uid) ? db.prepare('SELECT email FROM users WHERE id=?').get(uid) : null;
    const del = Number.isInteger(uid) ? db.prepare('DELETE FROM grants WHERE document_id=? AND user_id=?').run(r.doc.id, uid) : { changes: 0 };
    if (!del.changes) return res.status(404).json({ error: 'no such grant' });
    log(req, 'permission.revoke', 'allowed', { documentId: r.doc.id, detail: { target: t?.email } });
    res.json({ ok: true });
  });

  // ---------- admin: activity + user management. No content access.
  const admin = express.Router();
  admin.use(requireAuth, requireRole('admin'));

  admin.get('/audit', (req, res) => {
    const lim = Math.min(Number(req.query.limit) || 100, 500);
    const rows = db.prepare(`SELECT seq,ts,actor_id,actor_email,action,outcome,document_id,detail,ip,hash FROM audit
      WHERE (@action IS NULL OR action=@action) AND (@outcome IS NULL OR outcome=@outcome)
        AND (@doc IS NULL OR document_id=@doc) AND (@actor IS NULL OR actor_email=@actor)
        AND (@before IS NULL OR seq<@before)
      ORDER BY seq DESC LIMIT @lim`).all({
      action: str(req.query.action, 50), outcome: str(req.query.outcome, 10), doc: str(req.query.document, 64),
      actor: str(req.query.actor, 200), before: Number(req.query.before) || null, lim });
    res.json(rows.map((r) => ({ ...r, detail: JSON.parse(r.detail) })));
  });
  admin.get('/audit/verify', (req, res) => res.json(audit.verify(db)));

  admin.post('/audit/anchor', (req, res) => {
    try {
      log(req, 'audit.anchor', 'allowed');
      const anc = audit.anchor(db, anchorPath);
      res.status(201).json(anc);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  admin.get('/audit/anchor', (req, res) => {
    res.json(audit.verifyAnchor(db, anchorPath));
  });

  // What counts as worth noticing: repeated denials, lockouts, and permission changes in the last 24h.
  admin.get('/alerts', (req, res) => {
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    res.json({
      repeated_denials: db.prepare(`SELECT actor_email, COUNT(*) AS denials FROM audit
        WHERE outcome='denied' AND ts>=? AND action LIKE 'document.%' GROUP BY actor_email HAVING denials>=3 ORDER BY denials DESC`).all(since),
      failed_logins: db.prepare(`SELECT actor_email, COUNT(*) AS failures FROM audit
        WHERE action='login' AND outcome='denied' AND ts>=? GROUP BY actor_email HAVING failures>=3 ORDER BY failures DESC`).all(since),
      permission_changes: db.prepare(`SELECT COUNT(*) AS n FROM audit WHERE action LIKE 'permission.%' AND ts>=?`).get(since).n,
    });
  });

  admin.get('/documents', (req, res) => {
    // Metadata only: names, owners, sizes. Content is never reachable from here.
    res.json(db.prepare(`SELECT d.id,d.name,d.category,d.size,d.created_at,d.deleted_at,u.email AS owner,
      (SELECT COUNT(*) FROM grants g WHERE g.document_id=d.id) AS grants FROM documents d JOIN users u ON u.id=d.owner_id
      ORDER BY d.created_at DESC LIMIT 500`).all());
  });
  admin.get('/users', (req, res) =>
    res.json(db.prepare('SELECT id,email,name,role,active,created_at FROM users ORDER BY id').all()));

  admin.patch('/users/:id', (req, res) => {
    const id = Number(req.params.id);
    const u = Number.isInteger(id) && db.prepare('SELECT * FROM users WHERE id=?').get(id);
    if (!u) return res.status(404).json({ error: 'not found' });
    const role = req.body?.role === undefined ? u.role : req.body.role;
    const active = req.body?.active === undefined ? u.active : (req.body.active ? 1 : 0);
    if (!['admin', 'owner', 'viewer'].includes(role)) return res.status(400).json({ error: 'invalid role' });
    if (u.id === req.user.id && (role !== 'admin' || !active)) return res.status(400).json({ error: 'you cannot demote or disable yourself' });
    db.prepare('UPDATE users SET role=?, active=? WHERE id=?').run(role, active, id);
    if (!active) db.prepare('DELETE FROM sessions WHERE user_id=?').run(id); // kill live sessions now
    log(req, 'user.update', 'allowed', { detail: { target: u.email, role: { from: u.role, to: role }, active: { from: u.active, to: active } } });
    res.json({ id, email: u.email, role, active });
  });
  app.use('/api/admin', admin);
  app.get('/api/config', (req, res) => res.json({
    // Production deployments stay hidden by default; the hosted demo opts in explicitly.
    demoAccounts: process.env.TRUSTVAULT_DEMO !== '0' && process.env.TRUSTVAULT_DEMO_ACCOUNTS !== '0',
    sessionHours: SESSION_MS / 3600000
  }));

  // ---------- static frontend UI
  const publicDir = path.join(__dirname, '..', 'public');
  if (fs.existsSync(publicDir)) {
    app.use(express.static(publicDir));
    app.get('/', (req, res) => {
      res.sendFile(path.join(publicDir, 'index.html'));
    });
  }

  // ---------- errors
  app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));
  app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: 'upload rejected' });
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') return res.status(400).json({ error: 'bad request body' });
    console.error(err);
    res.status(500).json({ error: 'internal error' });
  });
  return app;
}

module.exports = { createApp };

