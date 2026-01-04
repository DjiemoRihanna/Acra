-- =============================================
-- SCHÉMA DE BASE DE DONNÉES ACRA
-- Correspond au cahier des charges fonctionnel
-- =============================================

BEGIN;

-- Créer le schéma principal
CREATE SCHEMA IF NOT EXISTS acra;
SET search_path TO acra, public;

-- =============================================
-- TABLE: users (UC01-UC13 - Administration & Profil)
-- =============================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    
    -- Rôles RBAC (5.5)
    role VARCHAR(50) NOT NULL DEFAULT 'analyst_junior' 
        CHECK (role IN ('admin', 'analyst_senior', 'analyst_junior', 'read_only')),
    
    -- État du compte
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    
    -- Sécurité (5.5)
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login TIMESTAMP,
    last_password_change TIMESTAMP DEFAULT NOW(),
    
    -- Préférences (UC10-UC13)
    theme VARCHAR(20) DEFAULT 'light' CHECK (theme IN ('light', 'dark')),
    language VARCHAR(10) DEFAULT 'fr',
    notification_preferences JSONB DEFAULT '{"email": true, "in_app": true}'::jsonb,
    
    -- Métadonnées
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- =============================================
-- TABLE: api_keys (UC08 - Threat Intelligence)
-- =============================================
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    service VARCHAR(50) NOT NULL CHECK (service IN ('abuseipdb', 'alienvault')),
    is_active BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- =============================================
-- TABLE: alerts (UC14-UC19 - Détection & Intelligence)
-- =============================================
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    
    -- Classification
    severity VARCHAR(10) NOT NULL CHECK (severity IN ('P1', 'P2', 'P3', 'P4')),
    category VARCHAR(50) NOT NULL
        CHECK (category IN ('malware', 'intrusion', 'data_exfiltration', 'scan', 'dos', 'anomaly')),
    
    -- Scores (5.2)
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    ti_score INTEGER DEFAULT 0 CHECK (ti_score BETWEEN 0 AND 100),
    ml_score INTEGER DEFAULT 0 CHECK (ml_score BETWEEN 0 AND 100),
    ueba_score INTEGER DEFAULT 0 CHECK (ueba_score BETWEEN 0 AND 100),
    context_score INTEGER DEFAULT 0 CHECK (context_score BETWEEN 0 AND 100),
    
    -- Sources de détection
    detection_source VARCHAR(50) NOT NULL
        CHECK (detection_source IN ('zeek', 'suricata', 'ml_engine', 'ti_feed', 'manual')),
    
    -- Adresses réseau
    source_ip INET NOT NULL,
    source_port INTEGER,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    protocol VARCHAR(10),
    
    -- Détails
    signature_id VARCHAR(255),
    signature_name VARCHAR(500),
    raw_event JSONB,
    
    -- Statut workflow
    status VARCHAR(20) DEFAULT 'new' 
        CHECK (status IN ('new', 'investigating', 'confirmed', 'false_positive', 'resolved')),
    
    assigned_to INTEGER REFERENCES users(id),
    investigation_notes TEXT,
    
    -- Métadonnées temporelles
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    
    -- Index pour performances
    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_risk_score (risk_score),
    INDEX idx_alerts_detected_at (detected_at)
);

-- =============================================
-- TABLE: threat_intelligence (2.1.1)
-- =============================================
CREATE TABLE threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(512) NOT NULL,
    indicator_type VARCHAR(50) NOT NULL
        CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash')),
    
    reputation_score INTEGER NOT NULL CHECK (reputation_score BETWEEN 0 AND 100),
    confidence_level INTEGER CHECK (confidence_level BETWEEN 0 AND 100),
    
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    asn INTEGER,
    country_code CHAR(2),
    
    source VARCHAR(100) NOT NULL DEFAULT 'abuseipdb'
        CHECK (source IN ('abuseipdb', 'alienvault', 'internal')),
    
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    
    UNIQUE (indicator, indicator_type, source),
    INDEX idx_ti_indicator (indicator)
);

-- =============================================
-- TABLE: response_actions (UC20-UC24 - Réponse Active)
-- =============================================
CREATE TABLE response_actions (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    
    action_type VARCHAR(50) NOT NULL
        CHECK (action_type IN ('block_ip', 'block_port', 'isolate_host', 'redirect_honeypot', 'tarpit')),
    
    target_ip INET,
    target_port INTEGER,
    target_protocol VARCHAR(10),
    
    triggered_by VARCHAR(50) NOT NULL
        CHECK (triggered_by IN ('auto', 'semi_auto', 'manual')),
    
    -- Mode NDR (5.3)
    response_mode VARCHAR(20) DEFAULT 'semi_auto'
        CHECK (response_mode IN ('off', 'semi_auto', 'auto')),
    
    status VARCHAR(20) DEFAULT 'pending'
        CHECK (status IN ('pending', 'executing', 'completed', 'failed')),
    
    execution_details JSONB,
    alert_id INTEGER REFERENCES alerts(id),
    initiated_by INTEGER REFERENCES users(id),
    
    created_at TIMESTAMP DEFAULT NOW(),
    executed_at TIMESTAMP,
    completed_at TIMESTAMP,
    
    INDEX idx_response_actions_status (status)
);

-- =============================================
-- TABLE: network_assets (UC25 - Actifs Vitaux)
-- =============================================
CREATE TABLE network_assets (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    mac_address MACADDR,
    hostname VARCHAR(255),
    
    asset_type VARCHAR(50) NOT NULL DEFAULT 'server'
        CHECK (asset_type IN ('server', 'workstation', 'network_device', 'container')),
    
    criticality_level INTEGER DEFAULT 1 CHECK (criticality_level BETWEEN 1 AND 5),
    is_critical BOOLEAN DEFAULT FALSE,
    
    -- Mode Survie (5.4)
    survival_ports INTEGER[] DEFAULT '{}',
    
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    open_ports INTEGER[] DEFAULT '{}',
    
    UNIQUE (ip_address),
    INDEX idx_network_assets_critical (is_critical)
);

-- =============================================
-- TABLE: audit_logs (UC09 - Audit)
-- =============================================
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    
    action_type VARCHAR(50) NOT NULL
        CHECK (action_type IN ('login', 'logout', 'create', 'update', 'delete', 'execute')),
    
    action_details TEXT NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    
    user_id INTEGER REFERENCES users(id),
    user_ip INET,
    user_agent TEXT,
    
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    performed_at TIMESTAMP DEFAULT NOW() NOT NULL,
    
    INDEX idx_audit_logs_user (user_id),
    INDEX idx_audit_logs_time (performed_at)
);

-- =============================================
-- TABLE: detection_rules (UC16 - Règles)
-- =============================================
CREATE TABLE detection_rules (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    
    rule_type VARCHAR(50) NOT NULL
        CHECK (rule_type IN ('signature', 'anomaly', 'threshold')),
    
    source VARCHAR(100) DEFAULT 'internal'
        CHECK (source IN ('internal', 'suricata', 'snort')),
    
    rule_content TEXT NOT NULL,
    default_severity VARCHAR(10) CHECK (default_severity IN ('P1', 'P2', 'P3', 'P4')),
    base_score INTEGER DEFAULT 50 CHECK (base_score BETWEEN 0 AND 100),
    
    is_active BOOLEAN DEFAULT TRUE,
    is_enabled BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    INDEX idx_detection_rules_active (is_active)
);

-- =============================================
-- FONCTIONS ET TRIGGERS
-- =============================================

-- Mise à jour automatique de updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers pour updated_at
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at 
    BEFORE UPDATE ON alerts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Fonction de calcul de score (5.2)
CREATE OR REPLACE FUNCTION calculate_risk_score(
    ml_score INTEGER,
    ueba_score INTEGER,
    ti_score INTEGER,
    context_score INTEGER
) RETURNS INTEGER AS $$
BEGIN
    -- Formule: 40% ML + 30% UEBA + 20% TI + 10% Contexte
    RETURN ROUND(
        (ml_score * 0.4) + 
        (ueba_score * 0.3) + 
        (ti_score * 0.2) + 
        (context_score * 0.1)
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================
-- DONNÉES INITIALES
-- =============================================

-- Utilisateur admin (mot de passe: Admin@123)
INSERT INTO users (email, username, password_hash, role, is_verified) VALUES
('admin@acra.local', 'admin', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'admin', TRUE);

-- Configuration système par défaut
INSERT INTO detection_rules (rule_id, rule_name, rule_type, rule_content, default_severity) VALUES
('TI-001', 'High Reputation Threat', 'signature', 'Threat Intelligence score >= 80', 'P1'),
('ML-001', 'Behavioral Anomaly', 'anomaly', 'Machine Learning anomaly detection', 'P2');

-- Actif critique exemple
INSERT INTO network_assets (ip_address, hostname, is_critical, survival_ports) VALUES
('192.168.1.100', 'web-server-01', TRUE, '{80, 443, 22}');

COMMIT;

SELECT '✅ Schéma ACRA créé avec succès!' as message;
SELECT COUNT(*) as tables_count FROM information_schema.tables WHERE table_schema = 'acra';
