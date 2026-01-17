from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import enum
import uuid

db = SQLAlchemy()

# --- ENUMS POUR LE RBAC (Exigence Daryl) ---
class UserRole(enum.Enum):
    ADMIN = "admin"
    ANALYST_SENIOR = "analyst_senior"
    ANALYST_JUNIOR = "analyst_junior"

# --- MODÈLE UTILISATEUR (UC04, UC11-UC13) ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    # UUID utilisé pour le cookie "Trusted Device" (Bypass MFA)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.ANALYST_JUNIOR)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Paramètres de Profil & Sécurité
    theme = db.Column(db.String(10), default='dark')         # UC13
    language = db.Column(db.String(5), default='fr')        # UC13
    notif_level = db.Column(db.String(5), default='P2')     # UC12
    two_factor_enabled = db.Column(db.Boolean, default=False) # UC11
    
    # Réinitialisation de mot de passe (UC05)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    # Relation vers les logs avec Option 2 (SET NULL)
    logs = db.relationship('AuditLog', back_populates='user')

    def __repr__(self):
        return f'<User {self.username}>'

# --- GESTION DES FLUX RÉSEAU (ZEEK INGESTION) ---
class NetworkFlow(db.Model):
    __tablename__ = 'network_flows'
    id = db.Column(db.BigInteger, primary_key=True)
    ts = db.Column(db.DateTime, index=True) 
    uid = db.Column(db.String(20), unique=True) # Pour ON CONFLICT DO UPDATE
    source_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    dest_ip = db.Column(db.String(45), index=True)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    service = db.Column(db.String(20))
    orig_bytes = db.Column(db.BigInteger, default=0)
    resp_bytes = db.Column(db.BigInteger, default=0)

# --- INVENTAIRE DES ASSETS RÉSEAU ---
class NetworkAsset(db.Model):
    __tablename__ = 'network_assets'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True)
    hostname = db.Column(db.String(255))
    asset_type = db.Column(db.String(50)) # Server, Workstation, IoT
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

# --- THREAT INTELLIGENCE (IOCs) ---
class ThreatIntelligence(db.Model):
    __tablename__ = 'threat_intelligence'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), index=True) # IP, Domain, Hash
    type = db.Column(db.String(50)) # Ex: Botnet CnC
    severity = db.Column(db.String(20))
    source = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- RÈGLES DE DÉTECTION ---
class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    logic = db.Column(db.JSON)
    is_enabled = db.Column(db.Boolean, default=True)

# --- JOURNAL D'AUDIT COMPLET (MIS À JOUR POUR audit_logger.py) ---
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False) # LOGIN_SUCCESS, USER_DELETE, etc.
    action_details = db.Column(db.Text)
    
    # Nouveaux champs pour correspondre à ton logger
    resource_type = db.Column(db.String(50)) # Ex: USER, ASSET
    resource_id = db.Column(db.String(50))   # ID de la ressource
    user_ip = db.Column(db.String(45))       # IP de l'utilisateur
    user_agent = db.Column(db.Text)          # Navigateur / Device
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    
    # ForeignKey avec ondelete='SET NULL'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relation inverse vers User
    user = db.relationship('User', back_populates='logs')

    def __repr__(self):
        return f'<AuditLog {self.action_type} - {self.performed_at}>'