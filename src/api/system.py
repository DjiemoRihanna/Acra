"""
System administration API endpoints
Handles audit logs, exports, and system management
"""
from flask import Blueprint, render_template, Response, jsonify
from flask_login import login_required, current_user
import io
import csv
from datetime import datetime,timedelta
from src.auth.decorators import role_required
from src.models import AuditLog, UserRole
from src.auth.audit_logger import log_event

system_bp = Blueprint('system', __name__)

# --- AUDIT LOGS MANAGEMENT (UC09) ---

@system_bp.route('/admin/audit-logs')
@login_required
@role_required(UserRole.ADMIN)
def view_audit_logs():
    """
    Affiche les actions effectuées sur le système.
    Filtre par défaut sur les 200 dernières actions.
    """
    logs = AuditLog.query.order_by(AuditLog.performed_at.desc()).limit(200).all()
    
    return render_template('admin/audit_logs.html', 
                           logs=logs, 
                           now=datetime.utcnow())

@system_bp.route('/admin/audit-logs/export')
@login_required
@role_required(UserRole.ADMIN)
def export_audit_logs():
    """
    Exporte l'historique complet pour analyse forensique externe.
    Chaque export est lui-même logué.
    """
    # LOG : On enregistre QUI exporte la base de logs
    log_event(
        "DATA_EXPORT", 
        "Exportation manuelle de la base d'audit complète (CSV)", 
        resource_type="AUDIT_LOGS"
    )

    # Récupérer tous les logs sans limite
    logs = AuditLog.query.order_by(AuditLog.performed_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # En-tête ultra-complet pour les enquêteurs
    writer.writerow(['ID', 'DATE_UTC', 'UTILISATEUR', 'ACTION', 'STATUT', 'IP_SOURCE', 'USER_AGENT', 'DETAILS_TECHNIQUES'])
    
    for log in logs:
        username = log.user.username if log.user else "Système/Inconnu"
        status = "SUCCESS" if log.success else "FAILED"
        writer.writerow([
            log.id, 
            log.performed_at, 
            username, 
            log.action_type, 
            status, 
            log.user_ip, 
            log.user_agent, 
            log.action_details
        ])
    
    output.seek(0)
    
    # Génération du nom de fichier avec horodatage
    filename = f"IREX_AUDIT_EXPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

# --- SYSTEM HEALTH ENDPOINTS ---

@system_bp.route('/health')
def health_check():
    """Endpoint de santé pour monitoring et load balancers"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "acra-api",
        "version": "1.0.0"
    })

@system_bp.route('/metrics')
@login_required
@role_required(UserRole.ADMIN)
def system_metrics():
    """Métriques système pour monitoring interne"""
    from src.models import User, NetworkAsset, Alert
    
    stats = {
        "users": {
            "total": User.query.count(),
            "active": User.query.filter_by(is_active=True).count(),
            "admins": User.query.filter_by(role=UserRole.ADMIN).count(),
        },
        "network": {
            "assets": NetworkAsset.query.count(),
            "active_assets": NetworkAsset.query.filter(
                NetworkAsset.last_seen > datetime.utcnow() - timedelta(minutes=5)
            ).count(),
        },
        "alerts": {
            "total": Alert.query.count(),
            "open": Alert.query.filter_by(status='OPEN').count(),
            "high_priority": Alert.query.filter_by(priority='HIGH').count(),
        },
        "audit": {
            "total_logs": AuditLog.query.count(),
            "last_24h": AuditLog.query.filter(
                AuditLog.performed_at > datetime.utcnow() - timedelta(hours=24)
            ).count(),
        }
    }
    
    return jsonify(stats)

# --- CONFIGURATION ENDPOINTS (pour UC16-UC17) ---

@system_bp.route('/config')
@login_required
@role_required(UserRole.ADMIN)
def get_config():
    """Récupère la configuration système (sécurisée)"""
    from src.config import Config
    
    safe_config = {
        "debug": Config.DEBUG,
        "environment": Config.ENV,
        "database": {
            "host": Config.DB_HOST[:10] + "..." if Config.DB_HOST else "not_set",
            "name": Config.DB_NAME,
        },
        "security": {
            "mfa_enabled": True,
            "password_min_length": 12,
            "session_timeout": Config.PERMANENT_SESSION_LIFETIME if hasattr(Config, 'PERMANENT_SESSION_LIFETIME') else 3600,
        },
        "limits": {
            "login_attempts": 5,
            "rate_limit": "5/minute",
        }
    }
    
    return jsonify(safe_config)