import eventlet
# Le monkey_patch DOIT être la toute première ligne du fichier
eventlet.monkey_patch()

import os
import time
import datetime
from flask import Flask, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

from src.models import db, User, UserRole

base_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
            static_folder=os.path.join(base_dir, 'static'),
            template_folder=os.path.join(base_dir, 'templates'))

# --- CONFIGURATION GÉNÉRALE ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-fortement-securise')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SÉCURITÉ & SESSIONS (REMEMBER ME) ---
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Durée du cookie "Se souvenir de moi" (7 jours)
app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(days=7)
# Empêche l'accès au cookie via JavaScript (Protection XSS)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
# Protection contre les attaques CSRF sur les cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# À mettre à True en production avec HTTPS
app.config['REMEMBER_COOKIE_SECURE'] = False 

# --- CONFIGURATION DB ENGINE (FIX LOCK ERROR) ---
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool,
}

# --- CONFIGURATION SOCKET.IO ---
socketio = SocketIO(app, 
                    cors_allowed_origins="*", 
                    async_mode='eventlet',
                    message_queue=os.getenv('REDIS_URL', 'redis://acra-redis:6379/0'))

db.init_app(app)

# --- GESTION DES CONNEXIONS (FLASK-LOGIN) ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES PRINCIPALES ---
@app.route('/')
def index():
    try:
        # Vérification de l'existence d'un admin pour le premier lancement
        admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
        if not admin_exists:
            return redirect(url_for('auth.setup'))
        return redirect(url_for('auth.login'))
    except Exception:
        # En cas d'erreur DB au démarrage, on tente d'envoyer vers setup
        return redirect(url_for('auth.setup'))

# --- BLUEPRINTS ---
from src.auth.routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

# --- INITIALISATION BASE DE DONNÉES ---
def setup_database():
    """Initialisation de la base de données avec retry automatique pour Docker"""
    with app.app_context():
        retries = 10
        while retries > 0:
            try:
                db.create_all()
                print("✅ Database & Tables Ready")
                return
            except OperationalError:
                retries -= 1
                print(f"⏳ Postgres n'est pas prêt... ({retries} essais restants)")
                time.sleep(2)

if __name__ == "__main__":
    # 1. Préparer la DB avant de lancer le serveur
    setup_database()
    
    # 2. Lancer le serveur avec SocketIO
    # Note : debug=True est activé ici, mais attention au reloader avec eventlet
    print("🚀 Démarrage du serveur ACRA sur http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)