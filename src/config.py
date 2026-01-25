import os

class Config:
    # --- SÉCURITÉ CORE ---
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-super-secure-soc-2024')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://user:pass@db:5432/acra')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- CONFIGURATION MAIL (Gmail) ---
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    # Utilise un "Mot de passe d'application" Gmail, pas ton pass habituel !
    MAIL_USERNAME = os.environ.get('MAIL_USER') 
    MAIL_PASSWORD = os.environ.get('MAIL_PASS')
    MAIL_DEFAULT_SENDER = ('ACRA SOC System', os.environ.get('MAIL_USER'))
    
    # --- RÉSEAU (Crucial pour les amis) ---
    # Remplace par l'IP de ton interface Point d'Accès (vérifie avec 'ip addr')
    BASE_URL = os.environ.get('BASE_URL', "http://192.168.1.130:5000")