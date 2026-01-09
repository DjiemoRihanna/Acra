from src.app import app
from src.models import User
with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print(f"Succès ! Admin trouvé : {admin.email}")
    else:
        print("Erreur : Utilisateur admin non trouvé dans la base.")
