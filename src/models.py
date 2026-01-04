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
