-- Shady Search private backend schema.
-- Import customer data only after verifying the source schema and backup.
-- Do not run this against production until the migration checks are complete.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- The final customers table must be created/imported from a verified source
-- inventory. These columns reflect the fields currently rendered by app.js.
-- Keep a stable source_id and all original columns during migration.
CREATE TABLE IF NOT EXISTS customers (
  source_id TEXT PRIMARY KEY,
  name TEXT,
  phone1 TEXT,
  phone2 TEXT,
  phone3 TEXT,
  area TEXT,
  street TEXT,
  description TEXT,
  building TEXT,
  floor TEXT,
  apartment TEXT,
  notes TEXT,
  search_blob TEXT
);
CREATE INDEX IF NOT EXISTS idx_customers_area ON customers(area);
CREATE INDEX IF NOT EXISTS idx_customers_phone1 ON customers(phone1);
CREATE INDEX IF NOT EXISTS idx_customers_phone2 ON customers(phone2);
CREATE INDEX IF NOT EXISTS idx_customers_phone3 ON customers(phone3);


-- Coarse login throttling keyed by a hash of IP + normalized username.
CREATE TABLE IF NOT EXISTS login_attempts (
  bucket_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_window ON login_attempts(window_start);
