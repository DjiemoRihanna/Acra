import os
import time
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from sqlalchemy.exc import OperationalError

# Import des modèles et Enums (en utilisant public par défaut)
from src.models import db, User, UserRole

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Utilisation des variables d'environnement Docker
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import et enregistrement des routes
from src.auth.routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

def setup_database():
    """Crée les tables et l'admin UC01 dès le démarrage."""
    with app.app_context():
        retries = 10
        while retries > 0:
            try:
                # 1. Création des tables (NetworkFlow, User, etc.)
                db.create_all()
                
                # 2. Vérification et création de l'admin (UC01)
                # Note : On compare avec l'Enum UserRole.ADMIN
                admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
                if not admin_exists:
                    print("🛠  Initialisation de l'administrateur système (UC01)...")
                    hashed_pw = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
                    admin = User(
                        email='admin@acra.local',
                        username='admin',
                        password_hash=hashed_pw,
                        role=UserRole.ADMIN,
                        is_active=True
                    )
                    db.session.add(admin)
                    db.session.commit()
                    print("✅ UC01 : Premier Administrateur créé avec succès.")
                
                print("✅ Database Ready") # Message attendu par le script test_soc.sh
                return
            except OperationalError:
                retries -= 1
                print(f"⏳ Postgres n'est pas prêt... ({retries} essais restants)")
                time.sleep(2)
            except Exception as e:
                print(f"❌ Erreur lors du setup : {e}")
                break

if __name__ == "__main__":
    # Appel direct du setup avant le run
    setup_database()
    app.run(host='0.0.0.0', port=5000)