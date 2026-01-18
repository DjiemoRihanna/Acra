import os
import random
import secrets
import re
import csv
import io
import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func
from src.models import db, User, UserRole, NetworkFlow, AuditLog, NetworkAsset
from src.auth.decorators import role_required
from flask_apscheduler import APScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, time, timedelta

limiter = Limiter(key_func=get_remote_address)
scheduler = APScheduler()
auth_bp = Blueprint('auth', __name__)

# ==========================================================
# 🛡️ SYSTÈME DE VISIBILITÉ TOTALE (AUDIT & TRACKING)
# ==========================================================

def log_event(action_type, details, resource_type=None, resource_id=None, success=True, error=None):
    """
    FONCTION MAÎTRESSE : Enregistre tout avec contexte complet.
    Savoir : QUI (User), QUAND (Date), D'OÙ (IP), COMMENT (Navigateur).
    """
    try:
        new_log = AuditLog(
            action_type=action_type,
            action_details=details,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=current_user.id if current_user.is_authenticated else None,
            user_ip=request.remote_addr,         # Capture de l'IP source
            user_agent=request.user_agent.string, # Capture de l'outil/OS
            success=success,
            error_message=str(error) if error else None
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        print(f"❌ ERREUR CRITIQUE LOGGING : {e}")
        db.session.rollback()

@auth_bp.after_app_request
def after_request_audit(response):
    """
    LOGGING AUTOMATIQUE : Capture les erreurs (404, 403, 500) 
    même si aucune route ne le gère explicitement.
    """
    if response.status_code >= 400:
        log_event(
            "HTTP_ERROR", 
            f"Accès anormal ou erreur sur {request.path}", 
            resource_type="SYSTEM",
            success=False, 
            error=f"Statut HTTP: {response.status_code}"
        )
    return response



# --- FONCTION UTILITAIRE DE VALIDATION ---
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

# --- ROUTE SETUP (UC01) ---
@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
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

        from src.app import bcrypt
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
            
            # LOG : Enregistre l'acte de naissance du système
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
            # LOG : Enregistre l'échec d'installation (tentative suspecte ?)
            log_event("SYS_SETUP_FAIL", "Échec de l'initialisation du compte admin", success=False, error=e)
            flash("Une erreur est survenue lors de la création du compte.", "danger")

    return render_template('auth/setup.html')

# --- ROUTE LOGIN (UC04 avec Bypass MFA) ---
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    admin_exists = User.query.filter_by(role=UserRole.ADMIN).first()
    if not admin_exists:
        return redirect(url_for('auth.setup'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember_me') else False
        
        user = User.query.filter_by(email=email).first()
        from src.app import bcrypt
        
        # 1. CAS : Identifiants corrects
        if user and user.is_active and bcrypt.check_password_hash(user.password_hash, password):
            # VERIFICATION DU COOKIE DE CONFIANCE (Bypass MFA)
            trusted_device = request.cookies.get('trusted_device')
            if trusted_device == user.uuid:
                login_user(user, remember=True)
                
                # LOG : Connexion réussie sans MFA
                log_event("AUTH_LOGIN", f"Connexion réussie via Trusted Device pour {user.username}", "USER", user.id)
                
                return redirect(url_for('auth.dashboard'))

            # SINON : Procédure MFA classique
            session['mfa_user_id'] = user.id
            session['mfa_code'] = str(random.randint(100000, 999999))
            session['remember_me'] = remember 
            
            # LOG : Initialisation MFA (on sait qu'il a le bon mot de passe)
            log_event("AUTH_MFA_REQ", f"Code MFA généré pour {user.username}", "USER", user.id)
            
            print(f"📧 [MFA] Code pour {user.email} : {session['mfa_code']}", flush=True)
            return redirect(url_for('auth.verify_mfa'))
        
        # 2. CAS : Échec de connexion (Mots de passe faux ou utilisateur inexistant)
        # Très important pour la sécurité : on logue l'IP source de l'attaquant
        log_event("AUTH_FAILED", f"Tentative de connexion échouée pour l'email: {email}", "USER", None, success=False, error="Identifiants invalides")
        
        flash("Identifiants invalides.", "danger")
            
    return render_template('auth/login.html')

# --- ROUTE VERIFY MFA (Avec création du jeton de confiance) ---
@auth_bp.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'mfa_user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code_client = request.form.get('code')
        if code_client == session.get('mfa_code'):
            user = User.query.get(session['mfa_user_id'])
            remember_choice = session.get('remember_me', False)
            
            login_user(user, remember=remember_choice)
            
            response = redirect(url_for('auth.dashboard'))

            # SI "REMEMBER ME" EST COCHÉ, ON POSE LE COOKIE DE CONFIANCE
            if remember_choice:
                # Le cookie expire dans 30 jours
                response.set_cookie('trusted_device', user.uuid, 
                                    max_age=30*24*60*60, 
                                    httponly=True, 
                                    samesite='Lax')

            db.session.add(AuditLog(action_type="AUTH_SUCCESS", 
                                    action_details=f"MFA Validée (Trusted Device: {remember_choice})", 
                                    user_id=user.id))
            db.session.commit()

            # Nettoyage session
            session.pop('mfa_code', None)
            session.pop('mfa_user_id', None)
            session.pop('remember_me', None)
            
            return response
        
        flash("Code incorrect.", "danger")
    return render_template('auth/mfa.html')

# --- ROUTE ACTIVATION ---
@auth_bp.route('/activate/<token>', methods=['GET', 'POST'])
def activate_account(token):
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

        from src.app import bcrypt
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
    # 1. Statistiques de base
    total_users = User.query.count()
    total_assets = NetworkAsset.query.count()
    audit_count = AuditLog.query.count() # Ajouté pour le template
    
    # 2. Simulation du statut de la sonde ( NDR )
    is_observing = True # On peut imaginer un test réel plus tard
    
    # 3. Top IPs Suspectes (pour ton tableau en bas)
    # On récupère les assets qui ont le plus de trafic comme "suspects" par défaut
    top_assets = NetworkAsset.query.order_by(
        (NetworkAsset.total_bytes_sent + NetworkAsset.total_bytes_received).desc()
    ).limit(5).all()
    
    top_ips = []
    for a in top_assets:
        top_ips.append({
            "ip": a.ip_address,
            "score": random.randint(10, 85), # Simulation de score de menace
            "alertes": random.randint(0, 5)   # Simulation d'alertes
        })

    # 4. Logique du graphique temporel
    today_start = datetime.combine(datetime.now().date(), time.min)
    historical_flows = NetworkFlow.query.filter(NetworkFlow.ts >= today_start)\
                                         .order_by(NetworkFlow.ts.asc()).all()

    labels = [f.ts.strftime('%H:%M:%S') for f in historical_flows]
    network_data = [round(((f.orig_bytes or 0) + (f.resp_bytes or 0)) / (1024 * 1024), 4) for f in historical_flows]

    if not labels:
        labels = [datetime.datetime.now().strftime('%H:%M:%S')]
        network_data = [0]

    # On renvoie TOUTES les variables attendues par index.html
    return render_template('dashboard/index.html', 
                           total_users=total_users, 
                           total_assets=total_assets,
                           audit_count=audit_count,
                           is_observing=is_observing,
                           labels=labels, 
                           network_data=network_data, 
                           top_ips=top_ips) # Important pour le tableau

# --- GESTION DES UTILISATEURS (ADMIN) ---
@auth_bp.route('/admin/users')
@login_required
@role_required(UserRole.ADMIN)
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@auth_bp.route('/admin/users/create', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN)
def create_user():
    username = request.form.get('username')
    email = request.form.get('email')
    role_str = request.form.get('role')

    new_user = User(
        username=username,
        email=email,
        password_hash=f"PENDING_ACTIVATION_{secrets.token_hex(8)}",
        role=UserRole[role_str.upper()],
        is_active=False
    )
    db.session.add(new_user)
    
    token = secrets.token_urlsafe(32)
    activation_link = url_for('auth.activate_account', token=token, email=email, _external=True)
    
    db.session.add(AuditLog(
        action_type="USER_INVITE",
        action_details=f"Admin {current_user.username} a invité {username} ({role_str})",
        user_id=current_user.id
    ))
    db.session.commit()
    print(f"📧 [INVITATION] Vers: {email} | Lien: {activation_link}", flush=True)
    
    flash(f"Invitation envoyée à {email}.", "success")
    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/admin/users/update', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN)
def update_user():
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
        
        # Détails du log pour savoir "qui a changé quoi"
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
        log_event("USER_UPDATE_FAIL", f"Erreur lors de la mise à jour de {old_username}", success=False, error=e)
        flash("Erreur lors de la mise à jour.", "danger")

    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/admin/users/toggle/<int:user_id>')
@login_required
@role_required(UserRole.ADMIN)
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Action impossible sur soi-même.", "danger")
    else:
        user.is_active = not user.is_active
        action = "ENABLED" if user.is_active else "DISABLED"
        db.session.add(AuditLog(action_type="USER_STATUS_CHANGE", 
                                action_details=f"Compte {user.username} : {action}", 
                                user_id=current_user.id))
        db.session.commit()
        flash(f"Statut de {user.username} modifié.", "info")
    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(UserRole.ADMIN)
def delete_user(user_id):
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
            
            # LOG : Action irréversible enregistrée avec l'identité du responsable
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
            log_event("USER_DELETE_ERROR", f"Erreur lors de la suppression de {username_deleted}", "USER", user_id, success=False, error=e)
            flash("Une erreur est survenue lors de la suppression.", "danger")
            
    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/logout')
@login_required
def logout():
    db.session.add(AuditLog(action_type="LOGOUT", 
                            action_details="Déconnexion volontaire", 
                            user_id=current_user.id))
    db.session.commit()
    logout_user()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for('auth.login'))

# --- GESTION DU PROFIL (UC10, UC11, UC12, UC13) ---
@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
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

            from src.app import bcrypt
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
                    db.session.add(AuditLog(action_type="PASSWORD_CHANGE", 
                                           action_details="Changement de mot de passe réussi (Profil)", 
                                           user_id=current_user.id))
                    db.session.commit()
                    flash("Mot de passe modifié avec succès.", "success")
            
        elif action == 'update_preferences':
            new_theme = request.form.get('theme')
            new_notif = request.form.get('notif_level')
            if new_theme: current_user.theme = new_theme
            if new_notif: current_user.notif_level = new_notif
            db.session.commit()
            flash("Préférences mises à jour.", "success")
            
        return redirect(url_for('auth.profile'))

    return render_template('profile/settings.html')

# --- ROUTE MOT DE PASSE OUBLIÉ (UC05) ---
@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = secrets.token_urlsafe(32)
            reset_link = url_for('auth.reset_password', token=token, email=email, _external=True)
            
            db.session.add(AuditLog(
                action_type="PASSWORD_RESET_REQ",
                action_details=f"Demande de réinitialisation pour {email}",
                user_id=user.id
            ))
            db.session.commit()
            print(f"📧 [RESET EMAIL] Vers: {email} | Lien: {reset_link}", flush=True)
        
        flash("Si cet email existe, un lien de réinitialisation a été envoyé.", "info")
        return redirect(url_for('auth.login'))

    return render_template('auth/reset.html', step="request")

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
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

        from src.app import bcrypt
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

    # --- CONSULTATION DES LOGS D'AUDIT (UC09 - ADMIN ONLY) ---
@auth_bp.route('/admin/audit-logs')
@login_required
@role_required(UserRole.ADMIN)
def view_audit_logs():
    """
    Affiche les actions effectuées sur le système.
    Filtre par défaut sur les 200 dernières actions.
    """
    # Récupération des logs triés par date décroissante
    logs = AuditLog.query.order_by(AuditLog.performed_at.desc()).limit(200).all()
    
    # On passe 'now' pour l'affichage de la dernière mise à jour dans le template
    return render_template('admin/audit_logs.html', 
                           logs=logs, 
                           now=datetime.utcnow())
# --- EXPORTATION DES LOGS ---
@auth_bp.route('/admin/audit-logs/export')
@login_required
@role_required(UserRole.ADMIN)
def export_audit_logs():
    """
    Exporte l'historique complet pour analyse forensique externe.
    Chaque export est lui-même logué.
    """
    # LOG : On enregistre QUI exporte la base de logs
    log_event("DATA_EXPORT", "Exportation manuelle de la base d'audit complète (CSV)", resource_type="AUDIT_LOGS")

    # Récupérer tous les logs sans limite
    logs = AuditLog.query.order_by(AuditLog.performed_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # En-tête ultra-complet pour les enquêteurs
    writer.writerow(['ID', 'DATE_UTC', 'UTILISATEUR', 'ACTION', 'STATUT', 'IP_SOURCE', 'USER_AGENT', 'DETAILS_TECHNIQUES'])
    
    for log in logs:
        username = log.user.username if log.user else "Système/Inconnu"
        status = "SUCCESS" if log.success else "FAILED"
        writer.writerow([
            log.id, 
            log.performed_at, 
            username, 
            log.action_type, 
            status, 
            log.user_ip, 
            log.user_agent, 
            log.action_details
        ])
    
    output.seek(0)
    
    # Génération du nom de fichier avec horodatage
    filename = f"IREX_AUDIT_EXPORT_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

def auto_export_logs():
    with scheduler.app.app_context():
        from src.models import AuditLog
        import csv
        
        # 1. Créer le dossier s'il n'existe pas
        export_dir = "exports/daily_audit"
        os.makedirs(export_dir, exist_ok=True)
        
        # 2. Nom du fichier avec la date du jour
        filename = f"audit_backup_{datetime.now().strftime('%Y%m%d')}.csv"
        filepath = os.path.join(export_dir, filename)
        
        # 3. Extraction des données
        logs = AuditLog.query.all()
        
        with open(filepath, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Date', 'User', 'Action', 'IP', 'Status'])
            for log in logs:
                writer.writerow([log.performed_at, log.user.username if log.user else "System", 
                                 log.action_type, log.user_ip, log.success])
        
        print(f"[*] Export automatique réussi : {filepath}")

# 4. Initialisation du scheduler (à mettre dans ton create_app ou au démarrage)
def init_scheduler(app):
    scheduler.init_app(app)
    scheduler.start()
    
    # Planification : Chaque jour à 23h59
    scheduler.add_job(id='daily_export', func=auto_export_logs, trigger='cron', hour=23, minute=59)

# --- API DE VISIBILITÉ RÉSEAU (ITÉRATION 1) ---
from datetime import datetime, timedelta

@auth_bp.route('/api/v1/network/topology')
@login_required
def get_topology_data():
    try:
        # --- SEUIL DE DÉCONNEXION (30 secondes) ---
        # Si last_seen est plus vieux que ce seuil, l'appareil est "offline"
        threshold = datetime.utcnow() - timedelta(seconds=30)
        
        assets = NetworkAsset.query.all()
        nodes = []
        edges = []

        # Point central (Gateway) - Toujours Online
        nodes.append({
            "data": {
                "id": "gw", 
                "label": "PASSERELLE", 
                "device_type": "router",
                "status": "online",
                "ip": "192.168.1.1"
            }
        })

        for asset in assets:
            # On utilise to_dict() qui contient déjà notre logique status/alive
            asset_info = asset.to_dict()
            
            # Déterminer si l'appareil est actif pour l'affichage des liens
            is_active = asset.last_seen > threshold
            current_status = "online" if is_active else "offline"

            # 1. Ajout du Noeud avec son STATUT TEMPS RÉEL
            nodes.append({
                "data": {
                    "id": str(asset.id),
                    "label": asset_info['label'],
                    "ip": asset_info['ip'],
                    "type": asset_info['type'],
                    "device_type": asset_info['device_type'], # Récupéré du modèle
                    "status": current_status,                 # Crucial pour le CSS
                    "usage": f"{asset_info.get('usage_mb', 0)} Mo",
                    "os": asset_info.get('os') or "Inconnu",
                    "last_seen": asset_info['last_seen_human']
                }
            })

            # 2. Création du lien (Edge) UNIQUEMENT si l'appareil est Online
            # Si l'appareil est déconnecté, le lien disparaît de la carte
            if is_active:
                edges.append({
                    "data": {
                        "id": f"e{asset.id}", 
                        "source": str(asset.id), 
                        "target": "gw"
                    }
                })

        return jsonify({
            "status": "success",
            "nodes": nodes,
            "edges": edges
        })

    except Exception as e:
        print(f"❌ Erreur Topologie: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- ROUTE POUR LA TOPOLOGIE ---
@auth_bp.route('/topology')
@login_required
def network_map():
    """Affiche la page de la topologie interactive"""
    return render_template('network/topology.html')