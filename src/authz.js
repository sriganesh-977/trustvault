// THE authorization decision. Every route that touches a document goes through authorize().
// Admins get NO special access to document content: they see metadata and the audit log only.
const RANK = { read: 1, edit: 2, owner: 3 };
const NEEDS = { view: 'read', download: 'read', edit: 'edit', delete: 'owner', share: 'owner' };

function levelFor(db, user, doc) {
  if (doc.owner_id === user.id) return 'owner';
  const g = db.prepare('SELECT level FROM grants WHERE document_id=? AND user_id=?').get(doc.id, user.id);
  return g ? g.level : null;
}

/** Returns { ok, doc, level, reason }. Reads the database fresh every call: revocation is immediate. */
function authorize(db, user, docId, action) {
  const need = NEEDS[action];
  if (!need) throw new Error(`unknown action ${action}`); // fail closed on programmer error
  if (!user || !user.active) return { ok: false, reason: 'inactive_user' };
  if (typeof docId !== 'string' || docId.length > 64) return { ok: false, reason: 'not_found' };
  const doc = db.prepare('SELECT * FROM documents WHERE id=? AND deleted_at IS NULL').get(docId);
  if (!doc) return { ok: false, reason: 'not_found' };
  const level = levelFor(db, user, doc);
  if (!level) return { ok: false, reason: 'no_grant' };
  if (RANK[level] < RANK[need]) return { ok: false, reason: 'insufficient_level', level };
  return { ok: true, doc, level };
}

module.exports = { authorize };
