-- P4 Foundation schema

CREATE TABLE IF NOT EXISTS users (
  id          TEXT    PRIMARY KEY,
  email       TEXT    NOT NULL UNIQUE,
  org_id      TEXT    REFERENCES organisations(id) ON DELETE SET NULL,
  role        TEXT    NOT NULL DEFAULT 'admin',
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS organisations (
  id          TEXT    PRIMARY KEY,
  name        TEXT    NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS brands (
  id          TEXT    PRIMARY KEY,
  org_id      TEXT    NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  is_primary  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS legitimate_assets (
  id           TEXT    PRIMARY KEY,
  org_id       TEXT    NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  type         TEXT    NOT NULL, -- domain | subdomain | ip | cidr | nameserver
  value        TEXT    NOT NULL,
  source       TEXT    NOT NULL DEFAULT 'user_provided', -- user_provided | discovered_confirmed
  confirmed_at INTEGER,
  UNIQUE(org_id, type, value)
);

CREATE TABLE IF NOT EXISTS monitored_domains (
  id            TEXT    PRIMARY KEY,
  org_id        TEXT    NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  domain        TEXT    NOT NULL,
  domain_norm   TEXT    NOT NULL, -- IDNA/lowercase normalised
  punycode      TEXT,
  risk_level    TEXT    NOT NULL DEFAULT 'lowest', -- highest|high|medium|low|lowest
  risk_score    INTEGER NOT NULL DEFAULT 0,
  classification TEXT   NOT NULL DEFAULT 'unknown', -- owned|legitimate|suspicious|potential_phishing|confirmed_malicious|unknown
  attack_type   TEXT,   -- typosquat|homoglyph|phishing_keyword|tld_variant|ct_discovered|manual
  similarity    REAL,
  brand_id      TEXT    REFERENCES brands(id),
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  last_scanned  INTEGER,
  next_scan_at  INTEGER,
  discovery_src TEXT    NOT NULL, -- ct_log|dns_reg|variant_gen|manual|community
  customer_note TEXT,
  review_status TEXT    NOT NULL DEFAULT 'pending', -- pending|reviewed|dismissed
  UNIQUE(org_id, domain_norm)
);

CREATE TABLE IF NOT EXISTS domain_intel (
  id              TEXT    PRIMARY KEY,
  domain_id       TEXT    NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
  scanned_at      INTEGER NOT NULL,
  resolves        INTEGER NOT NULL DEFAULT 0,
  a_records       TEXT,   -- JSON array
  ns_records      TEXT,
  mx_records      TEXT,
  cert_issuer     TEXT,
  cert_issued_at  INTEGER,
  cert_expires_at INTEGER,
  cert_sans       TEXT,   -- JSON array
  http_status     INTEGER,
  https_status    INTEGER,
  page_title      TEXT,
  content_type    TEXT,   -- parked|empty|login_page|business_site|unknown
  brand_detected  INTEGER NOT NULL DEFAULT 0,
  login_form      INTEGER NOT NULL DEFAULT 0,
  asn             INTEGER,
  hosting         TEXT,
  screenshot_key  TEXT
);

CREATE TABLE IF NOT EXISTS domain_events (
  id          TEXT    PRIMARY KEY,
  domain_id   TEXT    NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
  event_type  TEXT    NOT NULL, -- discovered|dns_changed|risk_changed|content_changed|cert_issued|customer_classified|takedown_requested
  occurred_at INTEGER NOT NULL,
  detail      TEXT,   -- JSON payload (old vs new values)
  risk_before TEXT,
  risk_after  TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email             ON users(email);
CREATE INDEX IF NOT EXISTS idx_brands_org              ON brands(org_id);
CREATE INDEX IF NOT EXISTS idx_assets_org              ON legitimate_assets(org_id);
CREATE INDEX IF NOT EXISTS idx_domains_org             ON monitored_domains(org_id);
CREATE INDEX IF NOT EXISTS idx_domains_risk            ON monitored_domains(org_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_domains_next_scan       ON monitored_domains(next_scan_at);
CREATE INDEX IF NOT EXISTS idx_domains_review          ON monitored_domains(org_id, review_status);
CREATE INDEX IF NOT EXISTS idx_intel_domain_time       ON domain_intel(domain_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_domain_time      ON domain_events(domain_id, occurred_at DESC);
