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
from src.core import init_scheduler
from src.auth.audit_logger import log_event
from src.models import User, UserRole

# --- IMPORTS POUR L'INGESTION ET L'EVENT BUS ---
from src.ingestion.packet_capture import TopologyCapture
from src.core.event_bus import bus

# --- IMPORTS POUR LA DÉTECTION ET LE ML (Itération 2) ---
from src.detection import init_detection
from src.ml import init_ml

# --- IMPORT DES BLUEPRINTS ---
from src.api import api_bp
from src.api.network import network_bp, network_html_bp
from src.api.system import system_bp
from src.api.alerts import alerts_bp , alerts_html_bp  # Nouveau blueprint pour les alertes\

base_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
            static_folder=os.path.join(base_dir, 'static'),
            template_folder=os.path.join(base_dir, 'templates'))

# --- CONFIGURATION GÉNÉRALE ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://acra_admin:changeme123@acra-postgres:5432/acra')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-fortement-securise')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SCHEDULER_ENABLED'] = os.getenv('SCHEDULER_ENABLED', 'True').lower() == 'true'

# --- CONFIGURATION SCANNER RESEAU ---
app.config['NETWORK_INTERFACE'] = os.getenv('NETWORK_INTERFACE', 'eth0') 
app.config['NETWORK_RANGE'] = os.getenv('NETWORK_RANGE', '192.168.1.0/24')

# --- CONFIGURATION THREAT INTELLIGENCE (Itération 2) ---
app.config['ABUSEIPDB_API_KEY'] = os.getenv('ABUSEIPDB_API_KEY', '')
app.config['ALIENVAULT_API_KEY'] = os.getenv('ALIENVAULT_API_KEY', '')
app.config['TI_CACHE_TTL'] = int(os.getenv('TI_CACHE_TTL', 3600))

# --- CONFIGURATION ML (Itération 2) ---
app.config['ML_RETRAIN_INTERVAL'] = int(os.getenv('ML_RETRAIN_INTERVAL', 3600))
app.config['ML_MODELS_PATH'] = os.getenv('ML_MODELS_PATH', '/app/data/ml_models')

# --- CONFIGURATION MAIL (GMAIL RÉEL) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'acranoreply@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'ftgn avso qpfg ewbl')
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
                    message_queue=os.getenv('REDIS_URL', 'redis://acra-redis:6379/0'),
                    logger=True,
                    engineio_logger=False)

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

# --- ENREGISTREMENT DES BLUEPRINTS ---
init_auth(app)  # Enregistre auth_bp
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(network_bp)  # API REST: /api/network/*
app.register_blueprint(network_html_bp)  # Page HTML: /network/topology
app.register_blueprint(system_bp)  # Pages système: /admin/*
app.register_blueprint(alerts_bp)  # API Alertes: /api/alerts/*
app.register_blueprint(alerts_html_bp)  # Pages HTML: /alerts/*

print(f"[ROUTES] ✓ API disponibles sur /api/*")
print(f"[ROUTES] ✓ API réseau: /api/network/*")
print(f"[ROUTES] ✓ API alertes: /api/alerts/*")
print(f"[ROUTES] ✓ Page topologie: /network/topology")
print(f"[ROUTES] ✓ Audit logs: /admin/audit-logs")
print(f"[ROUTES] ✓ Pages alertes: /alerts/list, /alerts/<id>")

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

# --- CONFIGURATION DES ÉVÉNEMENTS WEBSOCKET ---
def setup_websocket_events():
    """
    Configure les événements WebSocket pour la communication temps réel
    """
    from src.api.network import register_socketio_events
    register_socketio_events(socketio)
    
    # Configuration du bridge Redis -> WebSocket
    def redis_to_websocket():
        """Bridge entre Redis Pub/Sub et WebSocket"""
        import redis
        import json
        
        # Client Redis pour l'écoute
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://acra-redis:6379/0'), decode_responses=True)
        pubsub = redis_client.pubsub()
        
        # S'abonner aux canaux
        channels = [
            'scapy:devices', 'scapy:topology', 'scapy:packets',
            'suricata:alert', 'new_alert', 'threat_intel',
            'signature_match', 'ml:prediction', 'analyst_feedback'
        ]
        pubsub.subscribe(*channels)
        
        print("🎧 [WEBSOCKET] Bridge Redis -> WebSocket démarré")
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                channel = message['channel']
                try:
                    data = json.loads(message['data'])
                    
                    # Router vers le bon événement WebSocket
                    if channel == 'scapy:devices':
                        socketio.emit('scapy_device', data)
                    elif channel == 'scapy:topology':
                        socketio.emit('scapy_topology', data)
                    elif channel == 'new_alert':
                        socketio.emit('new_alert', data)
                    elif channel == 'threat_intel':
                        socketio.emit('threat_intel_update', data)
                        
                except Exception as e:
                    print(f"❌ [WEBSOCKET] Erreur bridge: {e}")
    
    # Démarrer le bridge dans un thread séparé
    import threading
    bridge_thread = threading.Thread(target=redis_to_websocket, daemon=True)
    bridge_thread.start()

# --- LANCEMENT DE L'INGESTION RÉSEAU ---
def start_network_ingestion():
    """
    Démarre l'ingestion réseau
    """
    if os.getenv('DISABLE_NETWORK_INGESTION', 'False').lower() == 'true':
        print("[INGESTION] Désactivé par variable d'environnement")
        return
    
    try:
        capture = TopologyCapture()
        print("[INGESTION] Interface réseau disponible pour API")
        
        bus.publish_system_status({
            'service': 'web',
            'status': 'online',
            'message': 'API réseau prête'
        })
        
    except Exception as e:
        print(f"[INGESTION] ❌ Erreur initialisation: {e}")

# --- INITIALISATION DES MOTEURS DE DÉTECTION (Itération 2) ---
def init_detection_engines():
    """
    Initialise tous les moteurs de détection
    """
    print("\n" + "="*50)
    print("🧠 INITIALISATION MOTEURS DE DÉTECTION (Itération 2)")
    print("="*50)
    
    with app.app_context():
        # Initialiser les moteurs de détection
        detection = init_detection(app)
        print("✅ Moteurs de détection initialisés")
        
        # Initialiser les composants ML
        ml = init_ml(app)
        print("✅ Composants Machine Learning initialisés")
        
        print("="*50 + "\n")
        
        return detection, ml

if __name__ == "__main__":
    setup_database()
    
    # --- INITIALISATION DES MOTEURS DE DÉTECTION ---
    detection_engines, ml_components = init_detection_engines()
    
    # --- CONFIGURATION WEBSOCKET ---
    setup_websocket_events()
    
    # --- INITIALISATION API RÉSEAU ---
    start_network_ingestion()
    
    print("=" * 50)
    print("🚀 Démarrage du serveur ACRA v2.0")
    print("=" * 50)
    print("📡 WebSocket: /socket.io")
    print("🔌 API REST: /api/*")
    print("🌐 Topologie: /network/topology")
    print("⚠️ Alertes: /alerts/list")
    print("🧠 ML: Actif")
    print("=" * 50)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)