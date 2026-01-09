from functools import wraps
from flask import abort, request
from flask_login import current_user
from src.auth.audit_logger import log_event

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return abort(401)
            
            # Vérification du rôle stocké en DB
            if current_user.role not in allowed_roles:
                log_event(
                    action_type="execute",
                    details=f"Accès refusé (RBAC) à {request.path}",
                    resource_type="system_route",
                    resource_id=request.path,
                    success=False,
                    error_message=f"Role {current_user.role} not authorized"
                )
                return abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator
