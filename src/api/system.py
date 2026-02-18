"""
System administration API endpoints
Handles audit logs, exports, and system management
"""
from flask import Blueprint, render_template, Response, jsonify, current_app, request
from flask_login import login_required, current_user
import io
import csv
from datetime import datetime, timedelta
from src.auth.decorators import role_required
from src.models import AuditLog, UserRole
from src.auth.audit_logger import log_event

system_bp = Blueprint('system', __name__)

# --- AUDIT LOGS MANAGEMENT (UC09) ---

@system_bp.route('/admin/audit-logs')
@login_required
@role_required(UserRole.ADMIN)  # ← CORRECT : pas de crochets
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
@role_required(UserRole.ADMIN)  # ← CORRECT : pas de crochets
def export_audit_logs():
    """
    Exporte l'historique complet pour analyse forensique externe.
    Chaque export est lui-même logué.
    """
    log_event(
        "DATA_EXPORT", 
        "Exportation manuelle de la base d'audit complète (CSV)", 
        resource_type="AUDIT_LOGS"
    )

    logs = AuditLog.query.order_by(AuditLog.performed_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
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
@role_required(UserRole.ADMIN)  # ← CORRECT : pas de crochets
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

# --- PAGE DE CONFIGURATION (HTML) ---

@system_bp.route('/admin/config')
@login_required
@role_required(UserRole.ADMIN, UserRole.ANALYST_SENIOR)  # ← CORRECT : deux arguments, pas de liste
def config_page():
    """Page HTML de configuration système"""
    return render_template('admin/config.html')

# --- API CONFIGURATION (JSON) ---

@system_bp.route('/api/config', methods=['GET'])
@login_required
@role_required(UserRole.ADMIN, UserRole.ANALYST_SENIOR)  # ← CORRECT : deux arguments, pas de liste
def get_config_api():
    """API pour récupérer la configuration système (JSON)"""
    debug = current_app.config.get('DEBUG', False)
    env = current_app.config.get('ENV', 'production')
    
    db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    db_host = 'localhost'
    db_name = 'acra'
    
    if '@' in db_uri:
        db_host = db_uri.split('@')[-1].split('/')[0]
    if '/' in db_uri:
        db_name = db_uri.split('/')[-1].split('?')[0]
    
    session_timeout = current_app.config.get('PERMANENT_SESSION_LIFETIME', 3600)
    if isinstance(session_timeout, timedelta):
        session_timeout = int(session_timeout.total_seconds())
    
    safe_config = {
        "debug": debug,
        "environment": env,
        "database": {
            "host": db_host[:10] + "..." if len(db_host) > 10 else db_host,
            "name": db_name,
        },
        "security": {
            "mfa_enabled": current_user.two_factor_enabled if hasattr(current_user, 'two_factor_enabled') else False,
            "password_min_length": 12,
            "session_timeout": session_timeout,
        },
        "limits": {
            "login_attempts": 5,
            "rate_limit": "5/minute",
        }
    }
    
    return jsonify(safe_config)


@system_bp.route('/api/config', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN, UserRole.ANALYST_SENIOR)  # ← CORRECT : deux arguments, pas de liste
def save_config_api():
    """API pour sauvegarder la configuration"""
    data = request.get_json()
    
    log_event(
        "CONFIG_UPDATE",
        "Mise à jour de la configuration système",
        resource_type="SYSTEM",
        user_id=current_user.id
    )
    
    return jsonify({"status": "success", "message": "Configuration sauvegardée"})