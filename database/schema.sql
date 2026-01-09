BEGIN;

CREATE SCHEMA IF NOT EXISTS acra;
SET search_path TO acra, public;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) NOT NULL DEFAULT 'analyst_junior' CHECK (role IN ('admin', 'analyst_senior', 'analyst_junior', 'read_only')),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login TIMESTAMP,
    theme VARCHAR(20) DEFAULT 'light',
    language VARCHAR(10) DEFAULT 'fr',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    severity VARCHAR(10) NOT NULL,
    category VARCHAR(50) NOT NULL,
    risk_score INTEGER NOT NULL,
    ti_score INTEGER DEFAULT 0,
    ml_score INTEGER DEFAULT 0,
    ueba_score INTEGER DEFAULT 0,
    context_score INTEGER DEFAULT 0,
    source_ip INET NOT NULL,
    source_port INTEGER,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    protocol VARCHAR(10),
    detection_source VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'new',
    assigned_to INTEGER REFERENCES users(id),
    raw_event JSONB,
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    action_type VARCHAR(50) NOT NULL,
    action_details TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    user_ip INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    performed_at TIMESTAMP DEFAULT NOW() NOT NULL
);

-- Index corrects pour PostgreSQL
CREATE INDEX idx_alerts_severity ON alerts (severity);
CREATE INDEX idx_alerts_detected_at ON alerts (detected_at);
CREATE INDEX idx_audit_logs_user ON audit_logs (user_id);

-- Insertion de l'admin
INSERT INTO users (email, username, password_hash, role, is_verified) VALUES
('admin@acra.local', 'admin', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'admin', TRUE);

COMMIT;