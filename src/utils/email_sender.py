"""
Service d'envoi d'emails pour ACRA SOC
"""
from flask_mail import Message
from flask import current_app
from src.extensions import mail

def send_activation_email(email, activation_link, role="utilisateur"):
    """Envoi d'email d'activation avec IP réelle forcée"""
    try:
        msg = Message(
            subject="🔐 Activation de votre compte ACRA SOC",
            recipients=[email],
            body=f"Bonjour,\n\nVous êtes invité en tant que {role}.\nLien : {activation_link}",
            html=f"""
            <div style="font-family: sans-serif; max-width: 600px; margin: auto; border: 1px solid #d1d8e0; padding: 20px; border-radius: 8px;">
                <h2 style="color: #2c3e50; text-align: center;">🛡️ ACRA SOC SYSTEM</h2>
                <p>Bonjour,</p>
                <p>Une invitation a été créée pour vous rejoindre le SOC en tant que <strong>{role}</strong>.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{activation_link}" style="background: #28a745; color: white; padding: 14px 28px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">ACTIVER MON COMPTE</a>
                </div>
                <p style="color: #7f8c8d; font-size: 0.85em; border-top: 1px solid #eee; padding-top: 15px;">
                    <strong>Note de sécurité :</strong> Ce lien pointe vers l'adresse IP interne du SOC.<br>
                    URL : <code style="color: #e84393;">{activation_link}</code>
                </p>
            </div>
            """
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"❌ [SMTP ERROR] Échec envoi activation vers {email}: {str(e)}")
        return False

def send_password_reset_email(email, reset_link):
    """Envoi d'email de réinitialisation avec IP réelle forcée"""
    try:
        msg = Message(
            subject="🔄 Réinitialisation de mot de passe ACRA SOC",
            recipients=[email],
            body=f"Bonjour,\n\nLien de réinitialisation : {reset_link}",
            html=f"""
            <div style="font-family: sans-serif; max-width: 600px; margin: auto; border: 1px solid #d1d8e0; padding: 20px; border-radius: 8px;">
                <h2 style="color: #2c3e50; text-align: center;">🔄 RÉINITIALISATION</h2>
                <p>Bonjour,</p>
                <p>Cliquez sur le bouton ci-dessous pour modifier votre mot de passe d'analyste :</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background: #eb4d4b; color: white; padding: 14px 28px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">MODIFIER MON MOT DE PASSE</a>
                </div>
                <p style="color: #7f8c8d; font-size: 0.85em; border-top: 1px solid #eee; padding-top: 15px;">
                    Si vous n'êtes pas à l'origine de cette demande, sécurisez votre compte immédiatement.<br>
                    Lien direct : {reset_link}
                </p>
            </div>
            """
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"❌ [SMTP ERROR] Échec envoi reset vers {email}: {str(e)}")
        return False