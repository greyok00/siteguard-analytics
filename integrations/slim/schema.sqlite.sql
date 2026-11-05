-- SiteGuard standalone schema (SQLite 3.24+). Useful for single-server apps
-- and for exercising the middleware without MySQL; a high-volume site should
-- use MySQL or a real counter store instead.

CREATE TABLE IF NOT EXISTS sg_counters (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sg_counters_expires ON sg_counters (expires_at);

CREATE TABLE IF NOT EXISTS sg_distinct (
  subject TEXT NOT NULL,
  path_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  PRIMARY KEY (subject, path_hash, window_start)
);
CREATE INDEX IF NOT EXISTS sg_distinct_window ON sg_distinct (window_start);

CREATE TABLE IF NOT EXISTS sg_blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL DEFAULT 'ip',
  reason TEXT NOT NULL DEFAULT '',
  rule TEXT NOT NULL DEFAULT '',
  evidence TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT 'system',
  lifted_at TEXT
);
CREATE INDEX IF NOT EXISTS sg_blocks_expires ON sg_blocks (expires_at);

CREATE TABLE IF NOT EXISTS sg_incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  subject TEXT NOT NULL,
  rule TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'medium',
  evidence TEXT,
  request_count INTEGER NOT NULL DEFAULT 0,
  block_id INTEGER NOT NULL DEFAULT 0,
  resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS sg_incidents_ts ON sg_incidents (ts);
