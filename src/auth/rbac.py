"""
Role-Based Access Control (RBAC) - Gestion fine des permissions
Module plus avancé pour une gestion granulaire des permissions
"""

from enum import Enum

class Permission(Enum):
    """Définition des permissions granulaires"""
    # Permissions utilisateur
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_ALERTS = "view_alerts"
    VIEW_NETWORK = "view_network"
    
    # Permissions analyste
    ACKNOWLEDGE_ALERTS = "acknowledge_alerts"
    ADD_COMMENTS = "add_comments"
    ESCALATE_ALERTS = "escalate_alerts"
    
    # Permissions admin
    MANAGE_USERS = "manage_users"
    MANAGE_SYSTEM = "manage_system"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EXPORT_DATA = "export_data"
    
    # Permissions réponse
    EXECUTE_RESPONSE = "execute_response"
    MANAGE_FIREWALL = "manage_firewall"
    MANAGE_HONEYPOT = "manage_honeypot"

class Role:
    """Définition des rôles avec leurs permissions"""
    PERMISSIONS = {
        'USER': {
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_ALERTS,
            Permission.VIEW_NETWORK,
        },
        'ANALYST': {
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_ALERTS,
            Permission.VIEW_NETWORK,
            Permission.ACKNOWLEDGE_ALERTS,
            Permission.ADD_COMMENTS,
            Permission.ESCALATE_ALERTS,
        },
        'ADMIN': {
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_ALERTS,
            Permission.VIEW_NETWORK,
            Permission.ACKNOWLEDGE_ALERTS,
            Permission.ADD_COMMENTS,
            Permission.ESCALATE_ALERTS,
            Permission.MANAGE_USERS,
            Permission.MANAGE_SYSTEM,
            Permission.VIEW_AUDIT_LOGS,
            Permission.EXPORT_DATA,
            Permission.EXECUTE_RESPONSE,
            Permission.MANAGE_FIREWALL,
            Permission.MANAGE_HONEYPOT,
        }
    }
    
    @staticmethod
    def has_permission(role_name, permission):
        """Vérifie si un rôle a une permission spécifique"""
        return permission in Role.PERMISSIONS.get(role_name, set())
    
    @staticmethod
    def get_permissions(role_name):
        """Retourne toutes les permissions d'un rôle"""
        return Role.PERMISSIONS.get(role_name, set())

# Alias pour compatibilité avec les décorateurs existants
def check_permission(permission):
    """Vérifie si l'utilisateur courant a la permission requise"""
    from flask_login import current_user
    
    if not current_user.is_authenticated:
        return False
    
    return Role.has_permission(current_user.role.name, permission)

def permission_required(permission):
    """Décorateur pour vérifier une permission spécifique"""
    from functools import wraps
    from flask import abort
    from src.auth.audit_logger import log_event
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not check_permission(permission):
                log_event(
                    action_type="PERMISSION_DENIED",
                    details=f"Permission '{permission.value}' requise pour accéder à {request.path}",
                    resource_type="SYSTEM",
                    success=False,
                    error_message=f"User {current_user.username} lacks permission {permission.value}"
                )
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator