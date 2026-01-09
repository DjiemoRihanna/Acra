import random
from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from src.models import db, User
from src.auth.audit_logger import log_event

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    
    # Import local de bcrypt pour éviter les erreurs au démarrage
    from src.app import bcrypt
    
    if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
        # GÉNÉRATION CODE MFA
        mfa_code = str(random.randint(100000, 999999))
        session['mfa_user_id'] = user.id
        session['mfa_code'] = mfa_code
        
        # Dans src/auth/routes.py, remplace le print par :
        print(f"📧 [MFA] Code pour {user.email} : {mfa_code}", flush=True)
        
        log_event("login", f"Phase 1 réussie pour {user.email}", success=True)
        # On ne connecte pas encore l'utilisateur !
        return jsonify({"status": "mfa_required", "message": "Vérification MFA requise"}), 202

    return jsonify({"error": "Invalid credentials"}), 401

@auth_bp.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    user_id = session.get('mfa_user_id')
    code_server = session.get('mfa_code')
    code_client = data.get('code')

    if user_id and code_client == code_server:
        user = User.query.get(user_id)
        login_user(user) # ICI on connecte officiellement
        session.pop('mfa_code', None)
        log_event("login", f"MFA validé pour {user.username}", success=True)
        return jsonify({"status": "success", "role": user.role}), 200

    return jsonify({"error": "Code invalide"}), 401

@auth_bp.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    # ... (reste du code)
    if user_id and code_client == code_server:
        user = User.query.get(user_id)
        login_user(user)
        # On renvoie .value pour avoir "admin" en texte dans le JSON
        return jsonify({"status": "success", "role": user.role.value}), 200