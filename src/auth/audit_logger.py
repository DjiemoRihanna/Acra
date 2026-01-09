from flask import request
from flask_login import current_user
from src.models import db, AuditLog
from datetime import datetime

def log_event(action_type, details, resource_type=None, resource_id=None, success=True, error_message=None):
    """
    Enregistre une action dans la table acra.audit_logs.
    Supporte les appels depuis les routes (avec request) ou le système (sans request).
    """
    user_id = None
    # On récupère l'ID de l'utilisateur si une session Flask-Login est active
    try:
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
    except Exception:
        pass

    # Capture des métadonnées réseau
    try:
        remote_ip = request.remote_addr if request else "127.0.0.1"
        user_agent = request.user_agent.string if request else "System/Internal"
    except RuntimeError: # Hors contexte de requête Flask
        remote_ip = "127.0.0.1"
        user_agent = "System/Internal"

    log = AuditLog(
        action_type=action_type,
        action_details=details,
        resource_type=resource_type,
        resource_id=resource_id,
        user_id=user_id,
        user_ip=remote_ip,
        user_agent=user_agent,
        success=success,
        error_message=error_message,
        performed_at=datetime.utcnow()
    )

    try:
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"CRITICAL: Failed to write to audit_logs: {e}")