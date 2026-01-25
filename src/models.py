from src.extensions import db
from flask_login import UserMixin
from datetime import datetime
import enum
import uuid

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

    # Paramètres de Profil & Sécurité (UC11, UC12, UC13)
    theme = db.Column(db.String(10), default='dark')
    language = db.Column(db.String(5), default='fr')
    notif_level = db.Column(db.String(5), default='P2')
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    # Réinitialisation de mot de passe (UC05)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    # --- AJOUT POUR L'INVITATION DES AMIS ---
    invitation_token = db.Column(db.String(100), unique=True, nullable=True)

    # Relation vers les logs
    logs = db.relationship('AuditLog', back_populates='user')

    def __repr__(self):
        return f'<User {self.username}>'

# --- GESTION DES FLUX RÉSEAU (ZEEK INGESTION) ---
class NetworkFlow(db.Model):
    __tablename__ = 'network_flows'
    id = db.Column(db.BigInteger, primary_key=True)
    ts = db.Column(db.DateTime, index=True) 
    uid = db.Column(db.String(100), unique=True)
    source_ip = db.Column(db.String(100), index=True)
    source_port = db.Column(db.Integer)
    dest_ip = db.Column(db.String(100), index=True)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(100))
    service = db.Column(db.String(100))
    orig_bytes = db.Column(db.BigInteger, default=0)
    resp_bytes = db.Column(db.BigInteger, default=0)

# --- INVENTAIRE DES ASSETS RÉSEAU & TOPOLOGIE (Fusionné pour Itération 1) ---
# --- INVENTAIRE DES ASSETS RÉSEAU & TOPOLOGIE ---
class NetworkAsset(db.Model):
    __tablename__ = 'network_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(100), default="Inconnu")
    os_info = db.Column(db.String(100), default="Détection en cours...")
    
    # Type d'appareil pour les icônes (router, server, smartphone, computer)
    device_type = db.Column(db.String(50), default='computer') 
    
    # Statut par défaut
    status = db.Column(db.String(20), default='online') 
    
    # Distinction LAN vs Internet
    asset_type = db.Column(db.String(50), default='internal') 
    
    # Statistiques (initialisées à 0 pour éviter les NoneType)
    total_bytes_sent = db.Column(db.BigInteger, default=0)
    total_bytes_received = db.Column(db.BigInteger, default=0)
    
    # Liste des sites visités (UC "savoir ce qui a été fait")
    top_domains = db.Column(db.JSON, default=list) 
    
    # Mise à jour automatique de l'heure à chaque modification
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """
        Convertit l'objet en dictionnaire pour l'API de topologie.
        Inclut la sécurité contre les erreurs NoneType lors du calcul du trafic.
        """
        # 1. Sécurisation des calculs (évite l'erreur unsupported operand type +)
        sent = self.total_bytes_sent or 0
        received = self.total_bytes_received or 0
        usage_total_mb = round((sent + received) / (1024 * 1024), 2)
        
        # 2. Logique de détermination du statut "vivant" (online/offline)
        # Si l'appareil n'a pas été vu depuis plus de 60 secondes, il est offline
        from datetime import datetime as dt
        if self.last_seen:
            diff = (dt.utcnow() - self.last_seen).total_seconds()
            is_alive = "online" if diff < 60 else "offline"
        else:
            is_alive = "offline"

        # 3. Retourne le dictionnaire formaté pour le JSON de l'API
        return {
            "id": self.id,
            "ip": self.ip_address,
            "mac": self.mac_address,
            "label": self.hostname if (self.hostname and self.hostname != "Inconnu") else self.ip_address,
            "type": self.asset_type,
            "device_type": self.device_type,
            "os": self.os_info,
            "status": is_alive, 
            "usage_mb": usage_total_mb,
            "last_seen_human": self.last_seen.strftime('%H:%M:%S') if self.last_seen else "Inconnu",
            "sites": self.top_domains[:5] if self.top_domains else []
        }

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

# --- JOURNAL D'AUDIT COMPLET ---
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