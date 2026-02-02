"""
Authentication and Authorization package for ACRA SOC
Handles user management, RBAC, MFA, and audit logging.

Exports:
- auth_bp: Flask blueprint for authentication routes
- log_event: Centralized audit logging function
- role_required: Decorator for role-based access control
"""

from .routes import auth_bp
from .audit_logger import log_event
from .decorators import role_required

__version__ = '1.0.0'
__all__ = ['auth_bp', 'log_event', 'role_required', 'init_app']

# Fonction d'initialisation du package
def init_app(app):
    """Initialize auth package with Flask app"""
    app.register_blueprint(auth_bp)
    print(f"[AUTH] Authentication package initialized (v{__version__})")