"""
Centralisation de toutes les extensions Flask
Initialisées ici pour éviter les imports circulaires
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_apscheduler import APScheduler
from flask_mail import Mail
from flask_bcrypt import Bcrypt

# Base de données
db = SQLAlchemy()

# Gestion d'authentification
login_manager = LoginManager()

# Limiteur de requêtes (initialisé sans app d'abord)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Protection CSRF
csrf = CSRFProtect()

# Scheduler pour tâches planifiées
scheduler = APScheduler()

# Email
mail = Mail()

# Hashage de mots de passe
bcrypt = Bcrypt()

# Note: L'initialisation complète se fera dans app.py avec init_app(app)f