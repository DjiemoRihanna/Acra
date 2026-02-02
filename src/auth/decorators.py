"""
Décorateurs pour les contrôles d'accès et la journalisation d'audit
"""
from functools import wraps
from flask import abort, request
from flask_login import current_user
from src.models import db, AuditLog, UserRole
from src.auth.audit_logger import log_event  # <-- IMPORT AJOUTÉ

def role_required(*allowed_roles): 
    """
    Vérifie le rôle et LOGUE automatiquement les tentatives d'accès non autorisées.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Vérification de l'authentification
            if not current_user.is_authenticated:
                abort(401)
            
            # 2. Vérification de l'autorisation
            if current_user.role not in allowed_roles:
                # --- LOG DE TENTATIVE D'INTRUSION ---
                roles_attendus = [r.name for r in allowed_roles]
                details = (f"L'utilisateur {current_user.username} (Rôle: {current_user.role.name}) "
                           f"a tenté d'accéder à une ressource restreinte aux rôles: {roles_attendus}")

                # Utilisation du logger centralisé
                log_event(
                    action_type="UNAUTHORIZED_ACCESS",
                    details=details,
                    resource_type="SYSTEM",
                    resource_id=None,
                    success=False,
                    error_message="Tentative d'accès non autorisé"
                )

                # On refuse l'accès après avoir logué
                abort(403)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator