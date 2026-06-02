package db

import "database/sql"

// ApplySchemaPatches runs idempotent DDL for installs that already applied an older baseline schema.
func ApplySchemaPatches(db *sql.DB) error {
	if db == nil {
		return nil
	}
	const patch = `
CREATE TABLE IF NOT EXISTS vpn_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vpn_group_members (
  group_id TEXT NOT NULL,
  vpn_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (group_id, vpn_user_id),
  FOREIGN KEY(group_id) REFERENCES vpn_groups(id) ON DELETE CASCADE,
  FOREIGN KEY(vpn_user_id) REFERENCES vpn_users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vpn_group_members_user ON vpn_group_members(vpn_user_id);

DROP INDEX IF EXISTS idx_vpn_group_firewall_rules_group;
DROP TABLE IF EXISTS vpn_group_firewall_rules;

CREATE TABLE IF NOT EXISTS vpn_group_pcq (
  group_id TEXT PRIMARY KEY,
  download_limit_kbps INTEGER NULL,
  upload_limit_kbps INTEGER NULL,
  burst_download_kbps INTEGER NULL,
  burst_upload_kbps INTEGER NULL,
  pcq_classifier TEXT NOT NULL DEFAULT 'dual',
  is_disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(group_id) REFERENCES vpn_groups(id) ON DELETE CASCADE
);
`
	if _, err := db.Exec(patch); err != nil {
		return err
	}
	// Idempotent column addition for existing installs (ignore error if column already exists).
	_, _ = db.Exec(`ALTER TABLE vpn_group_pcq ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0`)

	const dnsPatch = `
CREATE TABLE IF NOT EXISTS dns_settings (
  id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  listen_addr TEXT NOT NULL DEFAULT '0.0.0.0:53',
  forward_upstreams TEXT NOT NULL DEFAULT '1.1.1.1 1.0.0.1',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`
	if _, err := db.Exec(dnsPatch); err != nil {
		return err
	}
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN listen_port INTEGER NOT NULL DEFAULT 53`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN core_dns_bin TEXT NOT NULL DEFAULT 'coredns'`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN listen_host TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN local_zone TEXT NOT NULL DEFAULT 'vpn.local'`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN local_zone_ttl INTEGER NOT NULL DEFAULT 300`)

	const dnsRecordsPatch = `
CREATE TABLE IF NOT EXISTS dns_records (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '@',
  record_type TEXT NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 300,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_dns_records_name ON dns_records(name);
`
	if _, err := db.Exec(dnsRecordsPatch); err != nil {
		return err
	}
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN block_ads_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN blocklist_urls TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN block_address TEXT NOT NULL DEFAULT '0.0.0.0'`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN cache_ttl INTEGER NOT NULL DEFAULT 300`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN query_log_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE dns_settings ADD COLUMN client_dns_host TEXT NOT NULL DEFAULT ''`)

	const dnsRulesPatch = `
CREATE TABLE IF NOT EXISTS dns_domain_rules (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  rule_type TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_dns_domain_rules_type ON dns_domain_rules(rule_type);
`
	if _, err := db.Exec(dnsRulesPatch); err != nil {
		return err
	}
	return nil
}
