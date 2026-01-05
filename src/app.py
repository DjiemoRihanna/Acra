from flask import Flask
from src.models import db
import os
import time
from sqlalchemy.exc import OperationalError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://acra_admin:changeme123@postgres:5432/acra')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def setup_database():
    """Tente de créer les tables avec un mécanisme de reconnexion."""
    with app.app_context():
        retries = 10
        while retries > 0:
            try:
                db.create_all()
                print("✅ Base de données connectée et tables créées !")
                return
            except OperationalError:
                retries -= 1
                print(f"⏳ Postgres n'est pas prêt... Nouvelle tentative dans 2s ({retries} essais restants)")
                time.sleep(2)
        print("❌ Impossible de se connecter à Postgres après plusieurs tentatives.")

# On lance la création des tables au démarrage
setup_database()

@app.route('/')
def index():
    return {"status": "ACRA System Running"}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
