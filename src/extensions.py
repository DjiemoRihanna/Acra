from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_bcrypt import Bcrypt

# On crée les instances ici SANS les lier à l'app tout de suite
# Cela permet de les importer dans les routes sans créer d'import circulaire
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
bcrypt = Bcrypt()