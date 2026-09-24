-- CyberShield AI — PostgreSQL reference schema
-- The FastAPI app auto-creates tables via SQLAlchemy; this file documents the
-- production schema and is useful for manual provisioning / review.

CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(128) UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    device_id   VARCHAR(128),
    model       VARCHAR(128),
    os_version  VARCHAR(32),
    created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id);

CREATE TABLE IF NOT EXISTS scan_results (
    id               SERIAL PRIMARY KEY,
    scan_id          VARCHAR(64) UNIQUE,
    device_id        VARCHAR(128),
    type             VARCHAR(32) NOT NULL,
    classification   VARCHAR(32),
    risk_score       INTEGER DEFAULT 0,
    severity         VARCHAR(16) DEFAULT 'SAFE',
    confidence       REAL DEFAULT 0,
    indicators       JSONB DEFAULT '[]',
    detection_methods JSONB DEFAULT '[]',
    recommendation   TEXT,
    raw_content      TEXT,            -- privacy: NULL unless STORE_RAW_CONTENT=true
    created_at       TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_results_device ON scan_results(device_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_created ON scan_results(created_at);

CREATE TABLE IF NOT EXISTS messages (
    id            SERIAL PRIMARY KEY,
    scan_id       VARCHAR(64),
    length        INTEGER DEFAULT 0,
    url_count     INTEGER DEFAULT 0,
    urgency_score INTEGER DEFAULT 0,
    label         VARCHAR(32),
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS urls (
    id         SERIAL PRIMARY KEY,
    scan_id    VARCHAR(64),
    url_hash   VARCHAR(64),
    host       VARCHAR(255),
    label      VARCHAR(32),
    probability REAL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);

CREATE TABLE IF NOT EXISTS files (
    id         SERIAL PRIMARY KEY,
    scan_id    VARCHAR(64),
    sha256     VARCHAR(64),
    filename   VARCHAR(255),
    mime_type  VARCHAR(128),
    size_bytes INTEGER DEFAULT 0,
    label      VARCHAR(32),
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256);

CREATE TABLE IF NOT EXISTS threat_chains (
    id            SERIAL PRIMARY KEY,
    device_id     VARCHAR(128),
    chain_types   JSONB DEFAULT '[]',
    combined_risk INTEGER DEFAULT 0,
    severity      VARCHAR(16),
    explanation   TEXT,
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS threat_events (
    id          SERIAL PRIMARY KEY,
    device_id   VARCHAR(128),
    scan_id     VARCHAR(64) REFERENCES scan_results(scan_id),
    chain_id    INTEGER REFERENCES threat_chains(id),
    event_type  VARCHAR(48) NOT NULL,
    severity    VARCHAR(16),
    risk_score  INTEGER DEFAULT 0,
    evidence    JSONB DEFAULT '{}',   -- minimal evidence only, no raw content
    detected_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_threat_events_device ON threat_events(device_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_time ON threat_events(detected_at);

CREATE TABLE IF NOT EXISTS security_alerts (
    id           SERIAL PRIMARY KEY,
    device_id    VARCHAR(128),
    title        VARCHAR(255),
    body         TEXT,
    severity     VARCHAR(16),
    acknowledged BOOLEAN DEFAULT false,
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_security_results (
    id                    SERIAL PRIMARY KEY,
    device_id             VARCHAR(128),
    package_name          VARCHAR(255),
    app_label             VARCHAR(32),
    risk_score            INTEGER DEFAULT 0,
    sensitive_permissions JSONB DEFAULT '[]',
    created_at            TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_anomalies (
    id            SERIAL PRIMARY KEY,
    device_id     VARCHAR(128),
    verdict       VARCHAR(16),
    anomaly_score REAL DEFAULT 0,
    destinations  JSONB DEFAULT '[]',
    created_at    TIMESTAMPTZ DEFAULT now()
);
