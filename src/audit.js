const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function digest(prev, e) {
  // JSON array gives an unambiguous encoding (no field-boundary tricks).
  return sha(JSON.stringify([prev, e.ts, e.actor_id, e.actor_email, e.action,
    e.outcome, e.document_id, e.detail, e.ip]));
}

/** Append one entry, chained to the previous one. Serialised by an immediate transaction. */
function record(db, { actor, actorEmail, action, outcome = 'info', documentId = null, detail = {}, ip = null }) {
  const run = db.transaction(() => {
    const last = db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').get();
    const prev = last ? last.hash : 'GENESIS';
    const e = {
      ts: new Date().toISOString(),
      actor_id: actor ? actor.id : null,
      actor_email: actor ? actor.email : (actorEmail ? String(actorEmail).slice(0, 200) : null),
      action, outcome,
      document_id: documentId,
      detail: JSON.stringify(detail),
      ip,
    };
    const hash = digest(prev, e);
    db.prepare(`INSERT INTO audit (ts,actor_id,actor_email,action,outcome,document_id,detail,ip,prev_hash,hash)
                VALUES (@ts,@actor_id,@actor_email,@action,@outcome,@document_id,@detail,@ip,@prev,@hash)`)
      .run({ ...e, prev, hash });
  });
  run.immediate();
}

/** Walk the whole chain. Returns { ok, entries, head, brokenAt }. */
function verify(db) {
  let prev = 'GENESIS', n = 0;
  for (const row of db.prepare('SELECT * FROM audit ORDER BY seq').iterate()) {
    if (row.prev_hash !== prev || digest(prev, row) !== row.hash) {
      return { ok: false, entries: n, brokenAt: row.seq, head: null };
    }
    prev = row.hash; n++;
  }
  return { ok: true, entries: n, head: prev, brokenAt: null };
}

/** Anchor current chain head to an external file outside the database to prevent tail truncation attacks. */
function anchor(db, anchorPath) {
  const v = verify(db);
  if (!v.ok) throw new Error('Cannot anchor an invalid or broken chain');
  const last = db.prepare('SELECT seq, ts, hash FROM audit ORDER BY seq DESC LIMIT 1').get();
  const data = {
    seq: last ? last.seq : 0,
    ts: last ? last.ts : null,
    head: v.head,
    entries: v.entries,
    anchored_at: new Date().toISOString()
  };
  fs.mkdirSync(path.dirname(anchorPath), { recursive: true });
  fs.writeFileSync(anchorPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  return data;
}

/** Verify current database state against the external anchor head. */
function verifyAnchor(db, anchorPath) {
  if (!fs.existsSync(anchorPath)) return { anchored: false, ok: true, message: 'No external anchor established yet' };
  try {
    const raw = fs.readFileSync(anchorPath, 'utf8');
    const anc = JSON.parse(raw);
    const v = verify(db);
    if (!v.ok) return { anchored: true, ok: false, brokenAt: v.brokenAt, reason: 'internal_chain_broken' };
    if (v.entries < anc.entries) {
      return { anchored: true, ok: false, reason: 'tail_truncation_detected', expectedEntries: anc.entries, actualEntries: v.entries };
    }
    if (anc.seq > 0) {
      const row = db.prepare('SELECT hash FROM audit WHERE seq=?').get(anc.seq);
      if (!row || row.hash !== anc.head) {
        return { anchored: true, ok: false, reason: 'anchor_head_mismatch', expectedHead: anc.head, actualHead: row?.hash || null };
      }
    }
    return { anchored: true, ok: true, anchor: anc, currentHead: v.head, currentEntries: v.entries };
  } catch (err) {
    return { anchored: true, ok: false, reason: 'invalid_anchor_file', error: err.message };
  }
}

module.exports = { record, verify, anchor, verifyAnchor };
