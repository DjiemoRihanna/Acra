"""
Extensions Flask centralisées
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_apscheduler import APScheduler
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO

# Initialisation des extensions
db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
scheduler = APScheduler()
mail = Mail()
bcrypt = Bcrypt()
socketio = SocketIO()

__all__ = [
    'db', 
    'login_manager', 
    'limiter', 
    'csrf', 
    'scheduler', 
    'mail', 
    'bcrypt',
    'socketio'
]