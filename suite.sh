#!/bin/bash
# add-missing-files.sh
# Description: Ajoute les fichiers manquants à la structure ACRA existante
# Usage: ./add-missing-files.sh

echo "🔧 Ajout des fichiers manquants à ACRA..."

# Vérifier qu'on est dans le dossier acra/
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Erreur: Vous devez être dans le dossier acra/"
    exit 1
fi

echo "✅ Structure ACRA détectée"

# =============================================
# 1. CRÉER LES DOSSIERS MANQUANTS
# =============================================
echo "📁 Création des dossiers manquants..."

# Créer seulement si n'existe pas
[ ! -d "database" ] && mkdir -p database
[ ! -d "database/migrations" ] && mkdir -p database/migrations
[ ! -d "database/seeds" ] && mkdir -p database/seeds
[ ! -d "docker/config" ] && mkdir -p docker/config

echo "✅ Dossiers vérifiés/créés"

# =============================================
# 2. CRÉER LE SCHÉMA SQL (SEULEMENT SI MANQUANT)
# =============================================
if [ ! -f "database/schema.sql" ]; then
    echo "🗄️  Création du schéma de base de données..."
    
    cat > database/schema.sql << 'EOF'
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
EOF
    
    echo "✅ Schéma créé: database/schema.sql"
else
    echo "✓ Schéma SQL déjà existant"
fi

# =============================================
# 3. CRÉER LE SCRIPT D'INIT DOCKER
# =============================================
if [ ! -f "docker/config/postgres-init.sh" ]; then
    echo "🐳 Création du script d'init Docker..."
    
    cat > docker/config/postgres-init.sh << 'EOF'
#!/bin/bash
# postgres-init.sh
# Initialisation de PostgreSQL pour ACRA

set -e

echo "🔧 Initialisation de la base de données ACRA..."

# Attendre que PostgreSQL soit prêt
until pg_isready -U "$POSTGRES_USER" -h localhost; do
    sleep 2
    echo "⏳ En attente de PostgreSQL..."
done

echo "✅ PostgreSQL est prêt"

# Créer la base si elle n'existe pas
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres <<-EOSQL
    SELECT 'CREATE DATABASE $POSTGRES_DB'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB')\gexec
    
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;
EOSQL

echo "✅ Base de données '$POSTGRES_DB' vérifiée/créée"

# Exécuter le schéma
echo "📦 Application du schéma ACRA..."
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/schema.sql

echo "🎉 Initialisation terminée avec succès!"
EOF
    
    chmod +x docker/config/postgres-init.sh
    echo "✅ Script Docker créé: docker/config/postgres-init.sh"
else
    echo "✓ Script Docker déjà existant"
fi

# =============================================
# 4. AJOUTER POSTGRES À DOCKER-COMPOSE (SI MANQUANT)
# =============================================
if ! grep -q "postgres:" docker-compose.yml; then
    echo "➕ Ajout du service PostgreSQL à docker-compose.yml..."
    
    # Sauvegarde
    cp docker-compose.yml docker-compose.yml.backup
    
    # Ajouter à la fin du fichier
    cat >> docker-compose.yml << 'EOF'

  # Base de données PostgreSQL
  postgres:
    image: postgres:15-alpine
    container_name: acra-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: acra
      POSTGRES_USER: acra_admin
      POSTGRES_PASSWORD: ${DB_PASSWORD:-changeme123}
    volumes:
      - ./data/pgdata:/var/lib/postgresql/data
      - ./database/schema.sql:/docker-entrypoint-initdb.d/schema.sql
      - ./docker/config/postgres-init.sh:/docker-entrypoint-initdb.d/init.sh
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U acra_admin"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - acra-network

  # Redis pour cache et événements
  redis:
    image: redis:7-alpine
    container_name: acra-redis
    restart: unless-stopped
    command: redis-server --appendonly yes
    volumes:
      - ./data/redis:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - acra-network

# Réseau Docker
networks:
  acra-network:
    driver: bridge
EOF
    echo "✅ PostgreSQL ajouté à docker-compose.yml"
else
    echo "✓ Service PostgreSQL déjà présent"
fi

# =============================================
# 5. CRÉER/CORRIGER LE FICHIER .env.example
# =============================================
if [ ! -f ".env.example" ]; then
    echo "⚙️  Création du fichier .env.example..."
    
    cat > .env.example << 'EOF'
# ===========================================
# ACRA - Variables d'Environnement
# ===========================================
# Copier en .env et modifier les valeurs

# Application Flask
FLASK_APP=src.app
FLASK_ENV=development
SECRET_KEY=change-this-in-production-12345

# Base de données PostgreSQL
DB_PASSWORD=secure_password_change_me
DATABASE_URL=postgresql://acra_admin:${DB_PASSWORD}@postgres/acra

# Redis
REDIS_URL=redis://redis:6379/0

# Ports
WEB_PORT=5000

# Threat Intelligence (2.1.1)
ABUSEIPDB_API_KEY=votre_cle_api_ici
ALIENVAULT_OTX_KEY=votre_cle_otx_ici

# Machine Learning (2.2.2)
ML_MODEL_PATH=/app/data/ml_models

# Performance (6.1)
MAX_DETECTION_LATENCY_MS=30000
MAX_RESPONSE_LATENCY_MS=2000

# Sécurité (5.5)
ADMIN_WHITELIST=192.168.1.100
FAILSAFE_ENABLED=true
AUTO_BLOCK_THRESHOLD=80
EOF
    echo "✅ .env.example créé"
else
    # Vérifier si les variables BD sont présentes
    if ! grep -q "DB_PASSWORD" .env.example; then
        echo "🔧 Ajout des variables BD à .env.example..."
        cat >> .env.example << 'EOF'

# Base de données PostgreSQL
DB_PASSWORD=secure_password_change_me
DATABASE_URL=postgresql://acra_admin:${DB_PASSWORD}@postgres/acra

# Redis
REDIS_URL=redis://redis:6379/0
EOF
        echo "✅ Variables BD ajoutées"
    else
        echo "✓ .env.example déjà complet"
    fi
fi

# =============================================
# 6. METTRE À JOUR src/models.py (SIMPLIFIÉ)
# =============================================
if [ -f "src/models.py" ]; then
    echo "🔄 Mise à jour de src/models.py avec des modèles de base..."
    
    # Créer une version simplifiée
    cat > src/models.py << 'EOF'
"""
Modèles SQLAlchemy pour ACRA
Correspondant au schéma database/schema.sql
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import enum

db = SQLAlchemy()

# =============================================
# ENUMS
# =============================================
class UserRole(enum.Enum):
    ADMIN = 'admin'
    ANALYST_SENIOR = 'analyst_senior'
    ANALYST_JUNIOR = 'analyst_junior'
    READ_ONLY = 'read_only'

class AlertSeverity(enum.Enum):
    P1 = 'P1'
    P2 = 'P2'
    P3 = 'P3'
    P4 = 'P4'

class AlertStatus(enum.Enum):
    NEW = 'new'
    INVESTIGATING = 'investigating'
    CONFIRMED = 'confirmed'
    FALSE_POSITIVE = 'false_positive'
    RESOLVED = 'resolved'

class ResponseMode(enum.Enum):
    OFF = 'off'
    SEMI_AUTO = 'semi_auto'
    AUTO = 'auto'

# =============================================
# MODÈLES PRINCIPAUX
# =============================================
class User(db.Model):
    """Utilisateurs ACRA (UC01-UC13)"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    
    role = db.Column(db.Enum(UserRole), default=UserRole.ANALYST_JUNIOR)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Préférences
    theme = db.Column(db.String(20), default='light')
    language = db.Column(db.String(10), default='fr')
    
    # Sécurité
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime)
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    alerts = db.relationship('Alert', backref='assigned_analyst', lazy=True)
    api_keys = db.relationship('ApiKey', backref='user', lazy=True)

class Alert(db.Model):
    """Alertes de sécurité (UC14-UC19)"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Classification
    severity = db.Column(db.Enum(AlertSeverity), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    
    # Scores (5.2)
    risk_score = db.Column(db.Integer, nullable=False)
    ti_score = db.Column(db.Integer, default=0)
    ml_score = db.Column(db.Integer, default=0)
    ueba_score = db.Column(db.Integer, default=0)
    context_score = db.Column(db.Integer, default=0)
    
    # Réseau
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer)
    destination_ip = db.Column(db.String(45), nullable=False)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    
    # Détection
    detection_source = db.Column(db.String(50), nullable=False)
    signature_id = db.Column(db.String(255))
    signature_name = db.Column(db.String(500))
    
    # Workflow
    status = db.Column(db.Enum(AlertStatus), default=AlertStatus.NEW)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    investigation_notes = db.Column(db.Text)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # JSON pour données brutes
    raw_event = db.Column(db.JSON)
    
    def calculate_risk_score(self):
        """Calcule le score de risque selon la formule (5.2)"""
        return int(
            (self.ml_score * 0.4) +
            (self.ueba_score * 0.3) +
            (self.ti_score * 0.2) +
            (self.context_score * 0.1)
        )

class ApiKey(db.Model):
    """Clés API pour Threat Intelligence (UC08)"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(255), unique=True, nullable=False)
    service = db.Column(db.String(50), nullable=False)  # 'abuseipdb', 'alienvault'
    
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class NetworkAsset(db.Model):
    """Actifs réseau (UC25)"""
    __tablename__ = 'network_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    
    asset_type = db.Column(db.String(50), default='server')
    criticality_level = db.Column(db.Integer, default=1)
    is_critical = db.Column(db.Boolean, default=False)
    
    # Mode Survie (5.4)
    survival_ports = db.Column(db.ARRAY(db.Integer), default=[])
    
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    open_ports = db.Column(db.ARRAY(db.Integer), default=[])

class ThreatIntelligence(db.Model):
    """Threat Intelligence (2.1.1)"""
    __tablename__ = 'threat_intelligence'
    
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(512), nullable=False)
    indicator_type = db.Column(db.String(50), nullable=False)  # 'ip', 'domain'
    
    reputation_score = db.Column(db.Integer, nullable=False)
    confidence_level = db.Column(db.Integer)
    
    threat_type = db.Column(db.String(100))
    malware_family = db.Column(db.String(100))
    
    source = db.Column(db.String(100), default='abuseipdb')
    
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    __table_args__ = (
        db.UniqueConstraint('indicator', 'indicator_type', 'source'),
    )

class ResponseAction(db.Model):
    """Actions de réponse (UC20-UC24)"""
    __tablename__ = 'response_actions'
    
    id = db.Column(db.Integer, primary_key=True)
    
    action_type = db.Column(db.String(50), nullable=False)  # 'block_ip', 'honeypot', 'tarpit'
    target_ip = db.Column(db.String(45))
    target_port = db.Column(db.Integer)
    
    triggered_by = db.Column(db.String(50), nullable=False)  # 'auto', 'semi_auto', 'manual'
    response_mode = db.Column(db.Enum(ResponseMode), default=ResponseMode.SEMI_AUTO)
    
    status = db.Column(db.String(20), default='pending')
    execution_details = db.Column(db.JSON)
    
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'))
    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    executed_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

class DetectionRule(db.Model):
    """Règles de détection (UC16)"""
    __tablename__ = 'detection_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(100), unique=True, nullable=False)
    rule_name = db.Column(db.String(255), nullable=False)
    
    rule_type = db.Column(db.String(50), nullable=False)  # 'signature', 'anomaly'
    source = db.Column(db.String(100), default='internal')
    
    rule_content = db.Column(db.Text, nullable=False)
    default_severity = db.Column(db.Enum(AlertSeverity))
    base_score = db.Column(db.Integer, default=50)
    
    is_active = db.Column(db.Boolean, default=True)
    is_enabled = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(db.Model):
    """Logs d'audit (UC09)"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    action_type = db.Column(db.String(50), nullable=False)
    action_details = db.Column(db.Text, nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(255))
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user_ip = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    success = db.Column(db.Boolean, nullable=False)
    error_message = db.Column(db.Text)
    
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)

# =============================================
# FONCTIONS UTILITAIRES
# =============================================
def init_db():
    """Initialise la base de données"""
    db.create_all()
    print("✅ Base de données initialisée")

if __name__ == "__main__":
    from src.app import app
    with app.app_context():
        init_db()
EOF
    
    echo "✅ src/models.py mis à jour avec les modèles de base"
else
    echo "✓ src/models.py déjà présent"
fi

# =============================================
# 7. CRÉER UN SCRIPT DE TEST BD
# =============================================
echo "🧪 Création d'un script de test de la base de données..."

cat > scripts/test-database.sh << 'EOF'
#!/bin/bash
# test-database.sh
# Teste la connexion et la structure de la base de données

set -e

echo "🧪 Test de la base de données ACRA..."

# Vérifier que Docker est en cours
if ! docker-compose ps | grep -q "acra-postgres"; then
    echo "❌ PostgreSQL n'est pas démarré"
    echo "💡 Lancez: docker-compose up -d postgres"
    exit 1
fi

# Test de connexion
echo "1. Test de connexion à PostgreSQL..."
if docker-compose exec -T postgres pg_isready -U acra_admin; then
    echo "✅ PostgreSQL est accessible"
else
    echo "❌ Impossible de se connecter à PostgreSQL"
    exit 1
fi

# Vérifier que la base existe
echo "2. Vérification de la base 'acra'..."
if docker-compose exec -T postgres psql -U acra_admin -d acra -c "\q" 2>/dev/null; then
    echo "✅ Base 'acra' existe"
else
    echo "❌ Base 'acra' n'existe pas"
    echo "💡 Réinitialisez: docker-compose down -v && docker-compose up -d postgres"
    exit 1
fi

# Vérifier les tables
echo "3. Vérification des tables..."
docker-compose exec -T postgres psql -U acra_admin -d acra -c "
    SELECT 
        table_name,
        (SELECT COUNT(*) FROM acra.\"\${table_name}\") as row_count
    FROM information_schema.tables 
    WHERE table_schema = 'acra' 
    ORDER BY table_name;
"

# Test des données admin
echo "4. Vérification de l'utilisateur admin..."
docker-compose exec -T postgres psql -U acra_admin -d acra -c "
    SELECT 
        email, 
        role, 
        is_active,
        created_at::date
    FROM acra.users 
    WHERE email = 'admin@acra.local';
"

echo ""
echo "🎉 Tests de base de données terminés avec succès!"
echo "📊 Pour explorer la BD: docker-compose exec postgres psql -U acra_admin -d acra"
EOF

chmod +x scripts/test-database.sh
echo "✅ Script de test créé: scripts/test-database.sh"

# =============================================
# 8. METTRE À JOUR LE README.md
# =============================================
echo "📖 Mise à jour du README.md..."

if [ -f "README.md" ]; then
    # Ajouter une section Base de Données si pas présente
    if ! grep -q "Base de données" README.md; then
        cat >> README.md << 'EOF'

## 🗄️ Base de Données

ACRA utilise PostgreSQL 15 avec le schéma suivant:

### Structure principale:
- `users` - Gestion des utilisateurs et RBAC
- `alerts` - Alertes de sécurité avec scoring
- `threat_intelligence` - Base de menaces
- `network_assets` - Inventaire des actifs réseau
- `response_actions` - Historique des contre-mesures
- `audit_logs` - Journal d'audit

### Initialisation:
```bash
# 1. Configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos valeurs

# 2. Démarrer PostgreSQL
docker-compose up -d postgres

# 3. Vérifier la création
./scripts/test-database.sh