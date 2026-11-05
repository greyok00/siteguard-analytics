-- SiteGuard standalone schema (MySQL 5.7+/MariaDB 10.4+).
-- Only the tables the middleware needs are created here; analytics tables
-- live in the WordPress plugin.

CREATE TABLE IF NOT EXISTS sg_counters (
  k varchar(191) NOT NULL,
  n bigint unsigned NOT NULL DEFAULT 0,
  expires_at datetime NOT NULL,
  PRIMARY KEY (k),
  KEY expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sg_distinct (
  subject varchar(48) NOT NULL,
  path_hash char(16) NOT NULL,
  window_start bigint unsigned NOT NULL,
  PRIMARY KEY (subject, path_hash, window_start),
  KEY window_start (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sg_blocks (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  subject varchar(48) NOT NULL,
  scope varchar(16) NOT NULL DEFAULT 'ip',
  reason varchar(191) NOT NULL DEFAULT '',
  rule varchar(64) NOT NULL DEFAULT '',
  evidence text NULL,
  created_at datetime NOT NULL,
  expires_at datetime NOT NULL,
  created_by varchar(32) NOT NULL DEFAULT 'system',
  lifted_at datetime NULL DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY subject (subject),
  KEY expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sg_incidents (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  ts datetime NOT NULL,
  subject varchar(48) NOT NULL,
  rule varchar(64) NOT NULL DEFAULT '',
  severity varchar(16) NOT NULL DEFAULT 'medium',
  evidence text NULL,
  request_count int unsigned NOT NULL DEFAULT 0,
  block_id bigint unsigned NOT NULL DEFAULT 0,
  resolved_at datetime NULL DEFAULT NULL,
  PRIMARY KEY (id),
  KEY ts (ts),
  KEY subject (subject)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
