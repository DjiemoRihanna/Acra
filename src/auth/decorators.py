from functools import wraps
from flask import abort, request
from flask_login import current_user
from src.models import db, AuditLog, UserRole

def role_required(*allowed_roles): 
    """
    Vérifie le rôle et LOGUE automatiquement les tentatives d'accès non autorisées.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Vérification de l'authentification
            if not current_user.is_authenticated:
                # Optionnel : On peut loguer ici aussi les accès anonymes sur zones protégées
                abort(401)
            
            # 2. Vérification de l'autorisation
            if current_user.role not in allowed_roles:
                # --- LOG DE TENTATIVE D'INTRUSION ---
                # On prépare le détail pour savoir ce qu'il essayait de faire
                roles_attendus = [r.name for r in allowed_roles]
                action_tentee = f"Accès refusé à la route : {request.path}"
                details = (f"L'utilisateur {current_user.username} (Rôle: {current_user.role.name}) "
                           f"a tenté d'accéder à une ressource restreinte aux rôles: {roles_attendus}")

                try:
                    log_entry = AuditLog(
                        action_type="UNAUTHORIZED_ACCESS",
                        action_details=details,
                        user_id=current_user.id,
                        user_ip=request.remote_addr,
                        user_agent=request.user_agent.string,
                        success=False
                    )
                    db.session.add(log_entry)
                    db.session.commit()
                except Exception as e:
                    print(f"❌ Erreur log décorateur: {e}")
                    db.session.rollback()

                # On refuse l'accès après avoir logué
                abort(403)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator