const path = require('path');

// Type is decided by file CONTENT (magic bytes), never by what the client claims.
const TYPES = {
  pdf:  { mime: 'application/pdf', test: (b) => b.subarray(0, 5).toString('latin1') === '%PDF-' },
  png:  { mime: 'image/png', test: (b) => b.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])) },
  jpg:  { mime: 'image/jpeg', test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  jpeg: { mime: 'image/jpeg', test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', test: zip },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', test: zip },
  txt:  { mime: 'text/plain', test: (b) => !b.includes(0) && Buffer.from(b.toString('utf8'), 'utf8').equals(b) },
};
function zip(b) { return b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4; }

/** Strip path parts, control chars and quotes; keep it short. Display only: never used as a disk path. */
function safeName(raw) {
  let n = path.basename(String(raw || '').replace(/\\/g, '/'));
  n = n.replace(/[\x00-\x1f\x7f"<>:*?|]/g, '').replace(/^\.+/, '').trim().slice(0, 120);
  return n || 'unnamed';
}

function inspectUpload(file) {
  if (!file || !file.buffer || file.buffer.length === 0) return { error: 'empty or missing file' };
  const name = safeName(file.originalname);
  const ext = path.extname(name).slice(1).toLowerCase();
  const t = TYPES[ext];
  if (!t) return { error: `file type .${ext || '?'} is not allowed` };
  if (!t.test(file.buffer)) return { error: 'file content does not match its extension' };
  return { name, mime: t.mime };
}

module.exports = { inspectUpload, safeName };
