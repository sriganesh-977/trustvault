const path = require('path');
const { open } = require('./db');
const { createApp } = require('./app');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
require('fs').mkdirSync(dataDir, { recursive: true });
const db = open(process.env.DB_PATH || path.join(dataDir, 'trustvault.db'));
const anchorPath = process.env.ANCHOR_PATH || path.join(dataDir, 'anchor.json');
const app = createApp({ db, blobDir: path.join(dataDir, 'blobs'), anchorPath });
app.set('trust proxy', process.env.TRUST_PROXY ? 1 : false);
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`TrustVault listening on :${port}`));
