from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import enum
import uuid

db = SQLAlchemy()

# Utilisation des Enums pour le RBAC (exigence Daryl)
class UserRole(enum.Enum):
    ADMIN = "admin"
    ANALYST_SENIOR = "analyst_senior"
    ANALYST_JUNIOR = "analyst_junior"

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

# --- TABLES ESSENTIELLES SOC RÉTABLIES ---

class NetworkFlow(db.Model):
    __tablename__ = 'network_flows'
    id = db.Column(db.BigInteger, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    source_ip = db.Column(db.String(45), index=True)
    dest_ip = db.Column(db.String(45), index=True)
    protocol = db.Column(db.String(10))
    bytes_sent = db.Column(db.BigInteger)

class NetworkAsset(db.Model):
    __tablename__ = 'network_assets'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True)
    hostname = db.Column(db.String(255))
    asset_type = db.Column(db.String(50)) # Server, Workstation, IoT

class ThreatIntelligence(db.Model):
    __tablename__ = 'threat_intelligence'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), index=True) # IP, Domain, Hash
    type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    source = db.Column(db.String(100))

class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    logic = db.Column(db.JSON)
    is_enabled = db.Column(db.Boolean, default=True)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50))
    action_details = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)