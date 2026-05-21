import db from './database';

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
`);

console.log('Migration complete.');