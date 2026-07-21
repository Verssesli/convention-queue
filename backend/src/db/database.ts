import Database, { Database as DatabaseType } from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const DB_PATH = process.env.DB_PATH ?? path.join(__dirname, '../../data/queue.db');
const DATA_DIR = path.dirname(DB_PATH);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db: DatabaseType = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Schema lives here, not in server.ts. CommonJS evaluates every `import` before
// the importing module's own body, so a migration written in server.ts would run
// *after* route modules that read the tables at import time (queue.ts seeds its
// "highest serving" cache that way). That works on an existing database and fails
// with "no such table" on a brand-new one. Creating the schema at the point the
// connection is opened means any module that imports `db` gets a ready database.
db.exec(`
    CREATE TABLE IF NOT EXISTS queue_entry (
        queue_id       TEXT    PRIMARY KEY,
        queue_number   INTEGER NOT NULL,
        joined_at      TEXT    NOT NULL,
        allowed_in_at  TEXT,
        expires_at     TEXT,
        left_queue     INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS catalogue_image (
        image_key   TEXT    PRIMARY KEY,
        image_url   TEXT    NOT NULL,
        image_order INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_queue_number  ON queue_entry(queue_number);
    CREATE INDEX IF NOT EXISTS idx_queue_waiting ON queue_entry(allowed_in_at, left_queue, queue_number);
`);

export default db;