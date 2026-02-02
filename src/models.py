from src.extensions import db
from flask_login import UserMixin
from datetime import datetime
import enum
import uuid

# --- ENUMS POUR LE RBAC ---
class UserRole(enum.Enum):
    ADMIN = "admin"
    ANALYST_SENIOR = "analyst_senior"
    ANALYST_JUNIOR = "analyst_junior"

# --- MODÈLE UTILISATEUR ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.ANALYST_JUNIOR)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    theme = db.Column(db.String(10), default='dark')
    language = db.Column(db.String(5), default='fr')
    notif_level = db.Column(db.String(5), default='P2')
    two_factor_enabled = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    invitation_token = db.Column(db.String(100), unique=True, nullable=True)

    logs = db.relationship('AuditLog', back_populates='user')

    def __repr__(self):
        return f'<User {self.username}>'

# --- GESTION DES FLUX RÉSEAU (Capturé par Scapy/Zeek) ---
class NetworkFlow(db.Model):
    __tablename__ = 'network_flows'
    id = db.Column(db.BigInteger, primary_key=True)
    ts = db.Column(db.DateTime, index=True, default=datetime.utcnow) 
    uid = db.Column(db.String(100), unique=True)
    source_ip = db.Column(db.String(100), index=True)
    source_port = db.Column(db.Integer)
    dest_ip = db.Column(db.String(100), index=True)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(100))
    service = db.Column(db.String(100))
    orig_bytes = db.Column(db.BigInteger, default=0) # Octets envoyés
    resp_bytes = db.Column(db.BigInteger, default=0) # Octets reçus
    duration = db.Column(db.Float, default=0.0)
    
    # Champ CRITIQUE pour "la totale" : stocke le domaine DNS capturé
    dns_query = db.Column(db.String(255), nullable=True) 

# --- INVENTAIRE DES ASSETS RÉSEAU & TOPOLOGIE ---
class NetworkAsset(db.Model):
    __tablename__ = 'network_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(100), default="Inconnu")
    os_info = db.Column(db.String(100), default="Détection en cours...")
    device_type = db.Column(db.String(50), default='computer') 
    status = db.Column(db.String(20), default='online') 
    asset_type = db.Column(db.String(50), default='internal') 
    
    # Statistiques cumulées réelles
    total_bytes_sent = db.Column(db.BigInteger, default=0)
    total_bytes_received = db.Column(db.BigInteger, default=0)
    
    # Liste des sites visités (JSON pour stocker l'historique récent)
    top_domains = db.Column(db.JSON, default=list) 
    
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    avg_traffic_mb = db.Column(db.Float, default=0.0) 
    avg_conn_count = db.Column(db.Float, default=0.0)
    is_critical_asset = db.Column(db.Boolean, default=False)

    def to_dict(self):
        """Convertit l'asset en données pour Cytoscape avec calcul réel du statut."""
        sent = self.total_bytes_sent or 0
        received = self.total_bytes_received or 0
        usage_total_mb = round((sent + received) / (1024 * 1024), 2)
        
        # Calcul dynamique : si pas vu depuis 2 mins = offline (rouge)
        if self.last_seen:
            diff = (datetime.utcnow() - self.last_seen).total_seconds()
            is_alive = "online" if diff < 120 else "offline"
        else:
            is_alive = "offline"

        return {
            "id": self.id,
            "ip": self.ip_address,
            "mac": self.mac_address,
            "label": self.hostname if (self.hostname and self.hostname != "Inconnu") else self.ip_address,
            "device_type": self.device_type,
            "os": self.os_info,
            "status": is_alive, 
            "usage_mb": usage_total_mb,
            "last_seen_human": self.last_seen.strftime('%H:%M:%S') if self.last_seen else "Jamais",
            # On renvoie les 5 derniers sites visités
            "sites": self.top_domains[-5:] if self.top_domains else ["Aucun site détecté"]
        }

# --- SYSTÈME D'ALERTES & SCORING ---
class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    ti_score = db.Column(db.Integer, default=0)
    ml_score = db.Column(db.Integer, default=0)
    ueba_score = db.Column(db.Integer, default=0)
    context_score = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(10), nullable=False) 
    category = db.Column(db.String(50), nullable=False) 
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    status = db.Column(db.String(20), default='new')
    detection_source = db.Column(db.String(50), default='ACRA-Brain')
    analyst_feedback = db.Column(db.Boolean, nullable=True) 
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- THREAT INTELLIGENCE (IOCs) ---
class ThreatIntelligence(db.Model):
    __tablename__ = 'threat_intelligence'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), index=True) 
    type = db.Column(db.String(50)) 
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

# --- JOURNAL D'AUDIT ---
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)
    action_details = db.Column(db.Text)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(50))
    user_ip = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='logs')

    def __repr__(self):
        return f'<AuditLog {self.action_type} - {self.performed_at}>'