const path = require('path');
const bcrypt = require('bcryptjs');
const { open } = require('./db');
const audit = require('./audit');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
require('fs').mkdirSync(dataDir, { recursive: true });
const db = open(process.env.DB_PATH || path.join(dataDir, 'trustvault.db'));
const pw = (k, d) => process.env[k] || d;
const users = [
  ['admin@trustvault.test', 'Ada Admin', 'admin', pw('SEED_ADMIN_PW', 'Admin-Demo-Pass-1')],
  ['owner@trustvault.test', 'Olu Owner', 'owner', pw('SEED_OWNER_PW', 'Owner-Demo-Pass-1')],
  ['viewer@trustvault.test', 'Vik Viewer', 'viewer', pw('SEED_VIEWER_PW', 'Viewer-Demo-Pass-1')],
];
for (const [email, name, role, p] of users) {
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) continue;
  db.prepare('INSERT INTO users (email,name,password_hash,role,created_at) VALUES (?,?,?,?,?)')
    .run(email, name, bcrypt.hashSync(p, 12), role, new Date().toISOString());
  audit.record(db, { actorEmail: 'seed', action: 'user.seed', detail: { email, role } });
}
console.log('Seeded demo accounts (change these passwords on any real deployment):');
users.forEach(([e, , r, p]) => console.log(`  ${r.padEnd(7)} ${e}  ${p}`));
