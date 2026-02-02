"""
Routes d'authentification et gestion des utilisateurs (UC01-UC13)
Version refactorisée selon architecture ACRA
"""
import random
import secrets
import re
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import login_user, logout_user, login_required, current_user
from src.extensions import db
from src.models import User, UserRole, AuditLog, NetworkAsset, NetworkFlow
from src.auth.decorators import role_required
from src.auth.audit_logger import log_event
from datetime import datetime, time
from src.extensions import limiter
from src.utils.network_utils import get_soc_ip
from src.utils.email_sender import send_activation_email, send_password_reset_email

auth_bp = Blueprint('auth', __name__)

# ==========================================================
# FONCTIONS UTILITAIRES
# ==========================================================

def get_password_errors(password):
    """
    Analyse le mot de passe selon la politique SOC :
    - 12 caractères minimum, 1 Majuscule, 1 Chiffre, 1 Caractère spécial
    """
    missing = []
    if len(password) < 12:
        missing.append("12 caractères minimum")
    if not re.search(r"[A-Z]", password):
        missing.append("une majuscule")
    if not re.search(r"[0-9]", password):
        missing.append("un chiffre")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        missing.append("un caractère spécial")
    return missing

# ==========================================================
# ROUTES D'AUTHENTIFICATION
# ==========================================================

# --- ROUTE SETUP (UC01) ---
@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initialisation du système - Premier administrateur"""
    admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
    if admin_exists:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_pw = request.form.get('confirm_password')

        if password != confirm_pw:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return render_template('auth/setup.html')

        errors = get_password_errors(password)
        if errors:
            flash(f"Mot de passe non conforme : {', '.join(errors)}.", "danger")
            return render_template('auth/setup.html')

        from src.extensions import bcrypt
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_admin = User(
            username=username,
            email=email,
            password_hash=hashed_pw,
            role=UserRole.ADMIN,
            is_active=True
        )
        
        try:
            db.session.add(new_admin)
            db.session.commit()
            
            log_event(
                action_type="SYS_SETUP", 
                details=f"Initialisation réussie du compte Administrateur racine : {username} ({email})",
                resource_type="USER",
                resource_id=new_admin.id
            )
            
            flash("Système initialisé avec succès ! Connectez-vous.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            log_event("SYS_SETUP_FAIL", "Échec de l'initialisation du compte admin", success=False, error_message=str(e))
            flash("Une erreur est survenue lors de la création du compte.", "danger")

    return render_template('auth/setup.html')

# --- ROUTE LOGIN (UC04 avec Bypass MFA) ---
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))

    admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
    if not admin_exists:
        return redirect(url_for('auth.setup'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember_me') else False
        
        user = User.query.filter_by(email=email).first()
        from src.extensions import bcrypt
        
        if user and user.is_active and bcrypt.check_password_hash(user.password_hash, password):
            # OPTION A : Bypass via Trusted Device
            trusted_device = request.cookies.get('trusted_device')
            if trusted_device == user.uuid:
                login_user(user, remember=remember)
                log_event("AUTH_LOGIN_TRUSTED", f"Accès direct : {user.username}", "USER", user.id)
                return redirect(url_for('auth.dashboard'))

            # OPTION B : Envoi du code MFA
            mfa_code = str(random.randint(100000, 999999))
            session['mfa_user_id'] = user.id
            session['mfa_code'] = mfa_code
            session['mfa_expiry'] = (datetime.now().timestamp() + 300) # Expire dans 5 min
            session['remember_me'] = remember 
            
            from flask_mail import Message
            from src.extensions import mail
            try:
                msg = Message(subject="🔐 Code de sécurité ACRA SOC",
                              recipients=[user.email],
                              body=f"Votre code : {mfa_code}")
                mail.send(msg)
                log_event("AUTH_MFA_SENT", f"MFA envoyé à {user.email}", "USER", user.id)
                flash("Un code de vérification a été envoyé par email.", "info")
                return redirect(url_for('auth.verify_mfa'))
            except Exception as e:
                flash("Erreur d'envoi du mail. Réessayez.", "danger")
                return render_template('auth/login.html')
        
        log_event("AUTH_FAILED", f"Échec pour {email}", "USER", None, False)
        flash("Identifiants invalides.", "danger")
            
    return render_template('auth/login.html')

# --- ROUTE VERIFY MFA (Version Sécurisée) ---
@auth_bp.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'mfa_user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        # 1. Vérification de l'expiration
        if datetime.now().timestamp() > session.get('mfa_expiry', 0):
            session.clear()
            flash("Le code a expiré. Veuillez vous reconnecter.", "warning")
            return redirect(url_for('auth.login'))

        # 2. Vérification du code
        if request.form.get('code') == session.get('mfa_code'):
            user = User.query.get(session['mfa_user_id'])
            remember_choice = session.get('remember_me', False)
            
            login_user(user, remember=remember_choice)
            response = make_response(redirect(url_for('auth.dashboard')))

            if remember_choice:
                # Cookie de confiance : 30 jours, HTTPOnly, Secure
                response.set_cookie('trusted_device', user.uuid, 
                                    max_age=30*24*60*60, httponly=True, 
                                    secure=True, samesite='Lax')

            log_event("AUTH_SUCCESS", f"MFA validé pour {user.username}", "USER", user.id)
            
            # Nettoyage
            session.pop('mfa_code', None)
            session.pop('mfa_user_id', None)
            return response
        
        flash("Code incorrect.", "danger")
    return render_template('auth/mfa.html')

# --- ROUTE ACTIVATION ---
@auth_bp.route('/activate/<token>', methods=['GET', 'POST'])
def activate_account(token):
    """Activation de compte utilisateur invité"""
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first_or_404()

    if user.is_active and not user.password_hash.startswith("PENDING_"):
        flash("Compte déjà activé.", "info")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_pw = request.form.get('confirm_password')

        if password != confirm_pw:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return render_template('auth/activate.html', token=token, email=email)

        errors = get_password_errors(password)
        if errors:
            flash(f"Sécurité insuffisante : {', '.join(errors)}.", "danger")
            return render_template('auth/activate.html', token=token, email=email)

        from src.extensions import bcrypt
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user.is_active = True
        
        try:
            db.session.commit()
            flash("Compte activé avec succès ! Connectez-vous.", "success")
            return redirect(url_for('auth.login'))
        except Exception:
            db.session.rollback()
            flash("Erreur lors de l'activation.", "danger")

    return render_template('auth/activate.html', token=token, email=email)

# --- ROUTE DASHBOARD ---
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    """Tableau de bord principal SOC"""
    # 1. Statistiques de base
    total_users = User.query.count()
    total_assets = NetworkAsset.query.count()
    audit_count = AuditLog.query.count()
    
    # 2. Simulation du statut de la sonde (NDR)
    is_observing = True  # À remplacer par vérification réelle
    
    # 3. Top IPs Suspectes
    top_assets = NetworkAsset.query.order_by(
        (NetworkAsset.total_bytes_sent + NetworkAsset.total_bytes_received).desc()
    ).limit(5).all()
    
    top_ips = []
    for a in top_assets:
        top_ips.append({
            "ip": a.ip_address,
            "score": random.randint(10, 85),  # Simulation de score de menace
            "alertes": random.randint(0, 5)   # Simulation d'alertes
        })

    # 4. Données pour graphique temporel
    today_start = datetime.combine(datetime.now().date(), time.min)
    historical_flows = NetworkFlow.query.filter(NetworkFlow.ts >= today_start)\
                                         .order_by(NetworkFlow.ts.asc()).all()

    labels = [f.ts.strftime('%H:%M:%S') for f in historical_flows]
    network_data = [round(((f.orig_bytes or 0) + (f.resp_bytes or 0)) / (1024 * 1024), 4) for f in historical_flows]

    if not labels:
        labels = [datetime.now().strftime('%H:%M:%S')]
        network_data = [0]

    return render_template('dashboard/index.html', 
                           total_users=total_users, 
                           total_assets=total_assets,
                           audit_count=audit_count,
                           is_observing=is_observing,
                           labels=labels, 
                           network_data=network_data, 
                           top_ips=top_ips)

# ==========================================================
# ROUTES ADMINISTRATION UTILISATEURS (UC07)
# ==========================================================

# --- GESTION DES UTILISATEURS (ADMIN) ---
@auth_bp.route('/admin/users')
@login_required
@role_required(UserRole.ADMIN)
def manage_users():
    """Page de gestion des utilisateurs"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@auth_bp.route('/admin/users/create', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN)
def create_user():
    username = request.form.get('username')
    email = request.form.get('email')
    role_str = request.form.get('role')

    # 1. Détection de l'IP réelle et forge du lien
    soc_ip = get_soc_ip()
    token = secrets.token_urlsafe(32)
    relative_url = url_for('auth.activate_account', token=token, email=email)
    activation_link = f"http://{soc_ip}:5000{relative_url}"

    # 2. Création de l'utilisateur avec un hash temporaire
    new_user = User(
        username=username,
        email=email,
        password_hash=f"PENDING_ACTIVATION_{secrets.token_hex(8)}",
        role=UserRole[role_str.upper()],
        is_active=False
    )
    
    try:
        # 3. Envoi du mail AVANT le commit pour garantir la cohérence
        if send_activation_email(email, activation_link, role_str):
            db.session.add(new_user)
            db.session.commit()
            log_event("USER_INVITE", f"Lien envoyé vers {soc_ip}", "USER", new_user.id)
            flash(f"✅ Invitation envoyée avec succès (IP détectée : {soc_ip})", "success")
        else:
            flash("❌ Impossible d'envoyer l'email. Vérifiez la configuration SMTP.", "danger")
            
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur système : {str(e)}", "danger")

    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/admin/users/update', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN)
def update_user():
    """Mise à jour d'un utilisateur"""
    user_id = request.form.get('user_id')
    user = User.query.get_or_404(user_id)
    
    old_username = user.username
    old_role = user.role.name
    
    new_username = request.form.get('username')
    new_email = request.form.get('email')
    new_role_str = request.form.get('role').upper()
    
    user.username = new_username
    user.email = new_email
    
    # Audit spécifique si le rôle change (Escalade de privilège ?)
    role_changed = False
    if old_role != new_role_str:
        user.role = UserRole[new_role_str]
        role_changed = True

    try:
        db.session.commit()
        
        details = f"Utilisateur {old_username} mis à jour par {current_user.username}."
        if role_changed:
            details += f" CHANGEMENT DE RÔLE : {old_role} -> {new_role_str}"
            
        log_event(
            action_type="USER_UPDATE",
            details=details,
            resource_type="USER",
            resource_id=user.id
        )
        
        flash(f"Profil de {user.username} mis à jour.", "success")
    except Exception as e:
        db.session.rollback()
        log_event("USER_UPDATE_FAIL", f"Erreur lors de la mise à jour de {old_username}", success=False, error_message=str(e))
        flash("Erreur lors de la mise à jour.", "danger")

    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/admin/users/toggle/<int:user_id>')
@login_required
@role_required(UserRole.ADMIN)
def toggle_user(user_id):
    """Activation/désactivation d'un utilisateur"""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Action impossible sur soi-même.", "danger")
    else:
        user.is_active = not user.is_active
        action = "ENABLED" if user.is_active else "DISABLED"
        db.session.add(AuditLog(
            action_type="USER_STATUS_CHANGE", 
            action_details=f"Compte {user.username} : {action}", 
            user_id=current_user.id
        ))
        db.session.commit()
        flash(f"Statut de {user.username} modifié.", "info")
    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN)
def delete_user(user_id):
    """Suppression d'un utilisateur"""
    user = User.query.get_or_404(user_id)
    
    # Sécurité : Empêcher de se supprimer soi-même
    if user.id == current_user.id:
        log_event("USER_DELETE_FAIL", "Tentative d'auto-suppression bloquée", "USER", user.id, success=False)
        flash("Suppression impossible sur votre propre compte.", "danger")
    else:
        username_deleted = user.username
        email_deleted = user.email
        
        try:
            db.session.delete(user)
            
            log_event(
                action_type="USER_DELETE", 
                details=f"Utilisateur supprimé : {username_deleted} ({email_deleted}) par l'admin {current_user.username}", 
                resource_type="USER", 
                resource_id=user_id,
                success=True
            )
            
            db.session.commit()
            flash(f"L'utilisateur {username_deleted} a été supprimé avec succès.", "success")
        except Exception as e:
            db.session.rollback()
            log_event("USER_DELETE_ERROR", f"Erreur lors de la suppression de {username_deleted}", "USER", user_id, success=False, error_message=str(e))
            flash("Une erreur est survenue lors de la suppression.", "danger")
            
    return redirect(url_for('auth.manage_users'))

# ==========================================================
# ROUTES PROFIL UTILISATEUR (UC10-UC13)
# ==========================================================

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Gestion du profil utilisateur"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_info':
            current_user.username = request.form.get('username')
            current_user.email = request.form.get('email')
            db.session.commit()
            flash("Informations personnelles mises à jour.", "success")
            
        elif action == 'change_password':
            old_pw = request.form.get('old_password')
            new_pw = request.form.get('new_password')
            confirm_pw = request.form.get('confirm_password')

            from src.extensions import bcrypt
            if not bcrypt.check_password_hash(current_user.password_hash, old_pw):
                flash("L'ancien mot de passe est incorrect.", "danger")
            elif new_pw != confirm_pw:
                flash("Les nouveaux mots de passe ne correspondent pas.", "danger")
            else:
                errors = get_password_errors(new_pw)
                if errors:
                    flash(f"Sécurité insuffisante : {', '.join(errors)}.", "danger")
                else:
                    current_user.password_hash = bcrypt.generate_password_hash(new_pw).decode('utf-8')
                    db.session.add(AuditLog(
                        action_type="PASSWORD_CHANGE", 
                        action_details="Changement de mot de passe réussi (Profil)", 
                        user_id=current_user.id
                    ))
                    db.session.commit()
                    flash("Mot de passe modifié avec succès.", "success")
            
        elif action == 'update_preferences':
            new_theme = request.form.get('theme')
            new_notif = request.form.get('notif_level')
            if new_theme: 
                current_user.theme = new_theme
            if new_notif: 
                current_user.notif_level = new_notif
            db.session.commit()
            flash("Préférences mises à jour.", "success")
            
        return redirect(url_for('auth.profile'))

    return render_template('profile/settings.html')

# ==========================================================
# ROUTES MOT DE PASSE OUBLIÉ (UC05)
# ==========================================================

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Forge du lien avec IP réelle
            soc_ip = get_soc_ip()
            token = secrets.token_urlsafe(32)
            relative_url = url_for('auth.reset_password', token=token, email=email)
            reset_link = f"http://{soc_ip}:5000{relative_url}"
            
            if send_password_reset_email(email, reset_link):
                log_event("PASSWORD_RESET_REQ", f"Reset envoyé via {soc_ip}", "USER", user.id)
        
        flash("Si cet email existe, un lien a été envoyé.", "info")
        return redirect(url_for('auth.login'))

    return render_template('auth/reset.html', step="request")

    
@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Réinitialisation du mot de passe avec token"""
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_pw = request.form.get('confirm_password')

        if password != confirm_pw:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return render_template('auth/reset.html', step="reset", token=token, email=email)

        errors = get_password_errors(password)
        if errors:
            flash(f"Critères manquants : {', '.join(errors)}", "danger")
            return render_template('auth/reset.html', step="reset", token=token, email=email)

        from src.extensions import bcrypt
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db.session.add(AuditLog(
            action_type="PASSWORD_RESET_SUCCESS",
            action_details=f"Réinitialisation réussie via token pour {email}",
            user_id=user.id
        ))
        db.session.commit()
        
        flash("Votre mot de passe a été réinitialisé. Connectez-vous.", "success")
        return redirect(url_for('auth.login'))

    return render_template('auth/reset.html', step="reset", token=token, email=email)

# ==========================================================
# ROUTE DE DÉCONNEXION
# ==========================================================

@auth_bp.route('/logout')
@login_required
def logout():
    """Déconnexion de l'utilisateur"""
    db.session.add(AuditLog(
        action_type="LOGOUT", 
        action_details="Déconnexion volontaire", 
        user_id=current_user.id
    ))
    db.session.commit()
    logout_user()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for('auth.login'))

# ==========================================================
# ROUTES DE TEST/REDIRECTION
# ==========================================================

@auth_bp.route('/')
def index():
    """Route racine - Redirection vers login ou dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    return redirect(url_for('auth.login'))