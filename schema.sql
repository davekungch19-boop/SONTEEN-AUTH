CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  expires_at TEXT,
  max_devices INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  note TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(key);
