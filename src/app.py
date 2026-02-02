"""
Application Flask principale - Point d'entrée
"""
import eventlet
# Le monkey_patch DOIT être la toute première ligne du fichier
eventlet.monkey_patch()

import os
import time
import datetime
from flask import Flask, redirect, url_for, request
from flask_socketio import SocketIO
from flask_login import login_required
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

# Import des extensions centralisées
from src.extensions import db, login_manager, limiter, csrf, scheduler, mail, bcrypt
from src.auth import init_app as init_auth
from src.api import init_app as init_api
from src.core import init_scheduler
from src.auth.audit_logger import log_event
from src.models import User, UserRole

# --- NOUVEL IMPORT : INGESTION RESEAU ---
from src.ingestion.packet_capture import start_ingestion

base_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
            static_folder=os.path.join(base_dir, 'static'),
            template_folder=os.path.join(base_dir, 'templates'))

# --- CONFIGURATION GÉNÉRALE ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://acra:acrapassword@acra-postgres:5432/acra')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-fortement-securise')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SCHEDULER_ENABLED'] = os.getenv('SCHEDULER_ENABLED', 'True').lower() == 'true'

# --- CONFIGURATION SCANNER RESEAU ---
# Assure-toi que ces valeurs correspondent à ton environnement réel
app.config['NETWORK_INTERFACE'] = os.getenv('NETWORK_INTERFACE', 'eth0') 
app.config['NETWORK_RANGE'] = os.getenv('NETWORK_RANGE', '192.168.1.0/24')

# --- CONFIGURATION MAIL (GMAIL RÉEL) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'acranoreply@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = ('ACRA SOC', app.config['MAIL_USERNAME'])

app.config['MAIL_SUPPRESS_SEND'] = False
app.config['TESTING'] = False
app.config['MAIL_DEBUG'] = False

# --- SÉCURITÉ & SESSIONS ---
app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(days=7)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = False

# --- ENGINE OPTIONS ---
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'poolclass': NullPool}

# --- INITIALISATION DES EXTENSIONS ---
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
mail.init_app(app)
limiter.init_app(app)
csrf.init_app(app)

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

# --- MIDDLEWARE DE LOGGING D'AUDIT ---
@app.after_request
def after_request_audit(response):
    if response.status_code >= 400:
        log_event(
            "HTTP_ERROR",
            f"Accès anormal ou erreur sur {request.path}",
            resource_type="SYSTEM",
            success=False,
            error_message=f"Statut HTTP: {response.status_code}"
        )
    return response

# --- ROUTE RACINE ---
@app.route('/')
def index():
    try:
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for('auth.dashboard'))
        
        admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
        if not admin_exists:
            return redirect(url_for('auth.setup'))
        return redirect(url_for('auth.login'))
    except Exception:
        return redirect(url_for('auth.setup'))

# --- INITIALISATION DES PACKAGES ---
init_auth(app)  # Enregistre auth_bp
init_api(app)   # Enregistre tous les blueprints API

print(f"[ROUTES] ✓ Topologie disponible sur /topology")

# --- INITIALISATION DU SCHEDULER ---
if app.config['SCHEDULER_ENABLED']:
    init_scheduler(app)
    print("[SCHEDULER] Tâches planifiées initialisées")

# --- INITIALISATION BASE DE DONNÉES ---
def setup_database():
    with app.app_context():
        retries = 10
        while retries > 0:
            try:
                db.create_all()
                print("✅ Database & Tables Ready")
                return
            except OperationalError as e:
                retries -= 1
                print(f"⏳ Postgres n'est pas prêt... ({retries} essais restants)")
                time.sleep(2)

if __name__ == "__main__":
    setup_database()
    
    # --- LANCEMENT DE L'INGESTION RÉELLE (SCANNER + SNIFFER) ---
    try:
        start_ingestion(app)
        print("[INGESTION] Scanner réseau démarré en arrière-plan")
    except Exception as e:
        print(f"[INGESTION] ❌ Erreur au démarrage du scanner: {e}")

    print("=" * 50)
    print("🚀 Démarrage du serveur ACRA sur http://0.0.0.0:5000")
    print("=" * 50)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)