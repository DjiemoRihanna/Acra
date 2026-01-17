from functools import wraps
from flask import abort
from flask_login import current_user
from src.models import UserRole

def role_required(*allowed_roles): 
    """
    Vérifie si current_user.role est parmi les rôles autorisés.
    L'usage de *allowed_roles permet de passer un ou plusieurs arguments.
    Exemple: @role_required(UserRole.ADMIN) 
    OU @role_required(UserRole.ADMIN, UserRole.ANALYST_SENIOR)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            # allowed_roles est maintenant un tuple (itérable)
            if current_user.role not in allowed_roles:
                abort(403)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator