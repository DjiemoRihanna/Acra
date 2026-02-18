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

# --- ENUMS POUR LES ALERTES ---
class AlertSeverity(enum.Enum):
    CRITICAL = "P1"
    HIGH = "P2"
    MEDIUM = "P3"
    LOW = "P4"
    INFO = "P5"

class AlertStatus(enum.Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"

class AlertCategory(enum.Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    SCAN = "scan"
    BRUTE_FORCE = "brute_force"
    DATA_EXFIL = "data_exfiltration"
    C2 = "command_and_control"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    SIGNATURE = "signature"
    UEBA = "ueba"
    THREAT_INTEL = "threat_intel"
    OTHER = "other"

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

    logs = db.relationship('AuditLog', back_populates='user', lazy='dynamic')
    investigations = db.relationship('Investigation', back_populates='analyst', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

# --- GESTION DES FLUX RÉSEAU (Capturé par Scapy/Zeek) ---
class NetworkFlow(db.Model):
    __tablename__ = 'network_flows'
    id = db.Column(db.BigInteger, primary_key=True)
    ts = db.Column(db.DateTime, index=True, default=datetime.utcnow) 
    uid = db.Column(db.String(100), unique=True, index=True)
    source_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    dest_ip = db.Column(db.String(45), index=True)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(100))
    service = db.Column(db.String(100))
    orig_bytes = db.Column(db.BigInteger, default=0)
    resp_bytes = db.Column(db.BigInteger, default=0)
    duration = db.Column(db.Float, default=0.0)
    
    # Classification interne/externe
    source_is_internal = db.Column(db.Boolean, default=False)
    dest_is_internal = db.Column(db.Boolean, default=False)
    
    # DNS
    dns_query = db.Column(db.String(255), nullable=True)
    
    # Relations
    alerts = db.relationship('Alert', backref='flow', lazy='dynamic')

    def __repr__(self):
        return f'<NetworkFlow {self.uid}>'

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
    
    # Statistiques cumulées
    total_bytes_sent = db.Column(db.BigInteger, default=0)
    total_bytes_received = db.Column(db.BigInteger, default=0)
    
    # Sites visités (JSON)
    top_domains = db.Column(db.JSON, default=list) 
    
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    avg_traffic_mb = db.Column(db.Float, default=0.0) 
    avg_conn_count = db.Column(db.Float, default=0.0)
    is_critical_asset = db.Column(db.Boolean, default=False)
    
    # Profilage UEBA (sera mis à jour par baselining.py)
    behavioral_profile = db.Column(db.JSON, default=dict)  # Profil comportemental
    deviation_score = db.Column(db.Float, default=0.0)  # Score d'écart (0-100)
    last_baseline_update = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    alerts_as_source = db.relationship('Alert', 
                                       foreign_keys='Alert.source_ip',
                                       primaryjoin='Alert.source_ip == NetworkAsset.ip_address',
                                       lazy='dynamic')
    alerts_as_dest = db.relationship('Alert',
                                     foreign_keys='Alert.destination_ip',
                                     primaryjoin='Alert.destination_ip == NetworkAsset.ip_address',
                                     lazy='dynamic')

    def to_dict(self):
        """Convertit l'asset en données pour Cytoscape."""
        sent = self.total_bytes_sent or 0
        received = self.total_bytes_received or 0
        usage_total_mb = round((sent + received) / (1024 * 1024), 2)
        
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
            "sites": self.top_domains[-5:] if self.top_domains else [],
            "is_critical": self.is_critical_asset,
            # CORRECTION: Gestion de None pour deviation_score
            "deviation_score": round(self.deviation_score, 1) if self.deviation_score is not None else 0.0
        }

# --- SYSTÈME D'ALERTES & SCORING ---
class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    
    # Scores
    ti_score = db.Column(db.Integer, default=0)      # Threat Intelligence (0-100)
    ml_score = db.Column(db.Integer, default=0)       # Machine Learning (0-100)
    ueba_score = db.Column(db.Integer, default=0)     # UEBA / Comportement (0-100)
    context_score = db.Column(db.Integer, default=0)  # Contexte (0-100)
    risk_score = db.Column(db.Integer, nullable=False) # Score final (0-100)
    
    # Classification
    severity = db.Column(db.Enum(AlertSeverity), nullable=False, default=AlertSeverity.LOW)
    category = db.Column(db.Enum(AlertCategory), nullable=False, default=AlertCategory.OTHER)
    status = db.Column(db.Enum(AlertStatus), nullable=False, default=AlertStatus.NEW)
    
    # Métadonnées de détection
    detection_source = db.Column(db.String(50), default='ACRA-Brain')  # signatures, ml, ueba, ti
    rule_id = db.Column(db.Integer, db.ForeignKey('detection_rules.id'), nullable=True)
    signature_id = db.Column(db.String(100), nullable=True)  # ID de signature Suricata/Snort
    
    # Informations réseau
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    flow_id = db.Column(db.BigInteger, db.ForeignKey('network_flows.id'), nullable=True)
    
    # Contexte
    description = db.Column(db.Text, nullable=True)
    raw_data = db.Column(db.JSON, default=dict)  # Données brutes de l'alerte
    evidence = db.Column(db.JSON, default=list)  # Preuves (logs, paquets)
    
    # Feedback analyste
    analyst_feedback = db.Column(db.Boolean, nullable=True)  # True = TP, False = FP
    analyst_comment = db.Column(db.Text, nullable=True)
    analyst_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    analyst = db.relationship('User', foreign_keys=[analyst_id])
    investigation = db.relationship('Investigation', backref='alert', uselist=False)

    def __repr__(self):
        return f'<Alert {self.uuid} - {self.severity.value} - {self.risk_score}>'

    def to_dict(self):
        """Convertit l'alerte en dictionnaire pour l'API."""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'risk_score': self.risk_score,
            'severity': self.severity.value if self.severity else None,
            'category': self.category.value if self.category else None,
            'status': self.status.value if self.status else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'description': self.description,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'scores': {
                'ti': self.ti_score,
                'ml': self.ml_score,
                'ueba': self.ueba_score,
                'context': self.context_score,
                'total': self.risk_score
            }
        }


# --- THREAT INTELLIGENCE (IOCs) ---
class ThreatIntelligence(db.Model):
    __tablename__ = 'threat_intelligence'
    
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), index=True, nullable=False) 
    type = db.Column(db.String(50))  # ip, domain, url, hash
    severity = db.Column(db.Integer, default=50)  # 0-100
    confidence = db.Column(db.Integer, default=50)  # 0-100
    source = db.Column(db.String(100))
    description = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    tags = db.Column(db.JSON, default=list)
    raw_data = db.Column(db.JSON, default=dict)
    
    # Statistiques
    times_seen = db.Column(db.Integer, default=1)
    alerts_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<ThreatIntelligence {self.indicator} - {self.severity}>'


# --- RÈGLES DE DÉTECTION ---
class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Type de règle
    rule_type = db.Column(db.String(50), default='signature')  # signature, correlation, custom
    
    # Logique de la règle
    logic = db.Column(db.JSON, nullable=False)  # Contient la configuration de la règle
    
    # Métadonnées
    severity = db.Column(db.Integer, default=50)  # 0-100
    category = db.Column(db.String(50), default='other')
    tags = db.Column(db.JSON, default=list)
    
    # Filtres
    source_ips = db.Column(db.JSON, default=list)
    destination_ips = db.Column(db.JSON, default=list)
    protocols = db.Column(db.JSON, default=list)
    ports = db.Column(db.JSON, default=list)
    
    # Contrôle
    is_enabled = db.Column(db.Boolean, default=True)
    is_system = db.Column(db.Boolean, default=False)  # Règle système (non modifiable)
    priority = db.Column(db.Integer, default=5)  # 1-10 (10 = priorité absolue)
    
    # Statistiques
    times_matched = db.Column(db.Integer, default=0)
    last_matched = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    alerts = db.relationship('Alert', backref='rule', lazy='dynamic')

    def __repr__(self):
        return f'<DetectionRule {self.name}>'


# --- INVESTIGATIONS ---
class Investigation(db.Model):
    __tablename__ = 'investigations'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Liens
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=True)
    analyst_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Statut
    status = db.Column(db.String(50), default='open')  # open, closed
    priority = db.Column(db.Integer, default=3)  # 1-5
    
    # Timeline
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)
    
    # Données
    notes = db.Column(db.JSON, default=list)  # Notes de l'analyste
    evidence = db.Column(db.JSON, default=list)  # Preuves collectées
    related_flows = db.Column(db.JSON, default=list)  # IDs des flux associés
    related_alerts = db.Column(db.JSON, default=list)  # IDs des alertes associées
    
    # Relations
    analyst = db.relationship('User', foreign_keys=[analyst_id])

    def __repr__(self):
        return f'<Investigation {self.name}>'


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
    performed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', back_populates='logs')

    def __repr__(self):
        return f'<AuditLog {self.action_type} - {self.performed_at}>'