import eventlet
# Le monkey_patch DOIT être la toute première ligne du fichier
eventlet.monkey_patch()

import os
import time
import datetime
from flask import Flask, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

# Import des extensions centralisées depuis src/extensions.py
from src.extensions import db, login_manager, mail, bcrypt
from src.models import User, UserRole

base_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
            static_folder=os.path.join(base_dir, 'static'),
            template_folder=os.path.join(base_dir, 'templates'))

# --- CONFIGURATION GÉNÉRALE ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-fortement-securise')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURATION MAIL (GMAIL RÉEL) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = '' 
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_DEFAULT_SENDER'] = ''
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_SUPPRESS_SEND'] = False
# --- SÉCURITÉ & SESSIONS ---
csrf = CSRFProtect(app)
app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(days=7)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = False # Mettre à True en production (HTTPS)

# --- ENGINE OPTIONS ---
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'poolclass': NullPool}

# --- INITIALISATION DES EXTENSIONS ---
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
mail.init_app(app) # Réparation du KeyError: 'mail'

# --- CONFIGURATION SOCKET.IO ---
socketio = SocketIO(app, 
                    cors_allowed_origins="*", 
                    async_mode='eventlet',
                    message_queue=os.getenv('REDIS_URL', 'redis://acra-redis:6379/0'))

# --- CONFIGURATION LOGIN ---
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
        admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
        if not admin_exists:
            return redirect(url_for('auth.setup'))
        return redirect(url_for('auth.login'))
    except Exception:
        return redirect(url_for('auth.setup'))

# --- ENREGISTREMENT DES BLUEPRINTS ---
from src.auth.routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

# --- INITIALISATION BASE DE DONNÉES ---
def setup_database():
    """Initialisation de la base de données avec retry automatique"""
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
    setup_database()
    
    # On importe ce dont on a besoin depuis les routes
    # Notez l'ajout de 'scheduler' dans l'import
    from src.auth.routes import init_scheduler, scan_network_assets, scheduler
    
    # On initialise le scheduler
    init_scheduler(app)
    
    # On ajoute la tâche seulement si elle n'existe pas déjà
    try:
        if not scheduler.get_job('net_scan'):
            scheduler.add_job(
                id='net_scan', 
                func=scan_network_assets, 
                trigger='interval', 
                seconds=60,
                replace_existing=True
            )
            print("⏰ [SCHEDULER] Tâche de scan réseau configurée (60s)")
    except Exception as e:
        print(f"⚠️ [SCHEDULER] Erreur lors de la configuration : {e}")
    
    print("🚀 Démarrage du serveur ACRA sur http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)