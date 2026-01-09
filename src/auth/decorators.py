from functools import wraps
from flask import abort
from flask_login import current_user
from src.models import UserRole

def role_required(allowed_roles):
    """Vérifie si current_user.role (Enum) est dans allowed_roles (liste d'Enums)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            # On vérifie si l'objet Enum de l'utilisateur est dans la liste
            if current_user.role not in allowed_roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator