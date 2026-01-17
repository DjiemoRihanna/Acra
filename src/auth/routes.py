import os
import random
import datetime
import secrets
import re
import csv
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func
from src.models import db, User, UserRole, NetworkFlow, AuditLog
from src.auth.decorators import role_required
from flask_apscheduler import APScheduler

scheduler = APScheduler()
auth_bp = Blueprint('auth', __name__)

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
            flash(f"Mot de passe non conforme. Critère(s) manquant(s) : {', '.join(errors)}.", "danger")
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
            flash("Système initialisé avec succès ! Connectez-vous.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash("Une erreur est survenue lors de la création du compte.", "danger")
            print(f"Erreur Setup: {e}")

    return render_template('auth/setup.html')

# --- ROUTE LOGIN (UC04 avec Bypass MFA) ---
@auth_bp.route('/login', methods=['GET', 'POST'])
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
        
        if user and user.is_active and bcrypt.check_password_hash(user.password_hash, password):
            # VERIFICATION DU COOKIE DE CONFIANCE (Bypass MFA)
            trusted_device = request.cookies.get('trusted_device')
            if trusted_device == user.uuid: # On compare l'UUID stocké dans le cookie
                login_user(user, remember=True)
                db.session.add(AuditLog(action_type="AUTH_BYPASS_MFA", 
                                        action_details="Connexion auto (Appareil de confiance)", 
                                        user_id=user.id))
                db.session.commit()
                return redirect(url_for('auth.dashboard'))

            # SINON : Procédure MFA classique
            session['mfa_user_id'] = user.id
            session['mfa_code'] = str(random.randint(100000, 999999))
            session['remember_me'] = remember 
            
            print(f"📧 [MFA] Code pour {user.email} : {session['mfa_code']}", flush=True)
            return redirect(url_for('auth.verify_mfa'))
        
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
    total_users = User.query.count()
    audit_count = AuditLog.query.count()
    today_start = datetime.datetime.combine(datetime.datetime.now().date(), datetime.time.min)
    
    historical_flows = NetworkFlow.query.filter(NetworkFlow.ts >= today_start)\
                                        .order_by(NetworkFlow.ts.asc()).all()

    labels = [f.ts.strftime('%H:%M:%S') for f in historical_flows]
    network_data = [round(((f.orig_bytes or 0) + (f.resp_bytes or 0)) / (1024 * 1024), 4) for f in historical_flows]

    if not labels:
        labels = [datetime.datetime.now().strftime('%H:%M:%S')]
        network_data = [0]

    top_ips = [{"ip": "192.168.1.101", "score": 95, "alertes": 12}]
    return render_template('dashboard/index.html', total_users=total_users, audit_count=audit_count, 
                           labels=labels, network_data=network_data, top_ips=top_ips)

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
    user.username = request.form.get('username')
    user.email = request.form.get('email')
    new_role_str = request.form.get('role')
    
    if user.role.name != new_role_str.upper():
        user.role = UserRole[new_role_str.upper()]
        db.session.add(AuditLog(action_type="USER_RANK_CHANGE", 
                                action_details=f"Nouveau rôle pour {user.username}: {new_role_str}", 
                                user_id=current_user.id))
    db.session.commit()
    flash(f"Profil de {user.username} mis à jour.", "success")
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
    if user.id == current_user.id:
        flash("Suppression impossible.", "danger")
    else:
        username_deleted = user.username
        db.session.delete(user)
        db.session.add(AuditLog(action_type="USER_DELETE", 
                                action_details=f"Utilisateur {username_deleted} supprimé par admin", 
                                user_id=current_user.id))
        db.session.commit()
        flash("Utilisateur supprimé.", "success")
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
                           now=datetime.datetime.utcnow())

# --- EXPORTATION DES LOGS ---
@auth_bp.route('/admin/audit-logs/export')
@login_required
@role_required(UserRole.ADMIN)
def export_audit_logs():
    # Récupérer tous les logs
    logs = AuditLog.query.order_by(AuditLog.performed_at.desc()).all()
    
    # Créer un fichier en mémoire
    output = io.StringIO()
    writer = csv.writer(output)
    
    # En-tête du CSV
    writer.writerow(['ID', 'Date (UTC)', 'Utilisateur', 'Action', 'Statut', 'IP', 'Details'])
    
    for log in logs:
        username = log.user.username if log.user else "Système"
        status = "SUCCESS" if log.success else "FAILED"
        writer.writerow([log.id, log.performed_at, username, log.action_type, status, log.user_ip, log.action_details])
    
    # Préparer la réponse pour le navigateur
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=audit_export.csv"}
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