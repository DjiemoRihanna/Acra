"""
Tâches planifiées et gestion du scheduler
Déplacé depuis routes.py
"""
import os
import csv
from datetime import datetime
from src.models import AuditLog
from src.auth.audit_logger import log_event

def auto_export_logs():
    """
    Export automatique quotidien des logs d'audit
    Planifié à 23h59 chaque jour
    """
    # Note: Cette fonction doit être appelée dans le contexte d'application
    from src.extensions import scheduler
    
    with scheduler.app.app_context():
        try:
            export_dir = "exports/daily_audit"
            os.makedirs(export_dir, exist_ok=True)
            
            filename = f"audit_backup_{datetime.now().strftime('%Y%m%d')}.csv"
            filepath = os.path.join(export_dir, filename)
            
            logs = AuditLog.query.all()
            
            with open(filepath, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(['Date', 'User', 'Action', 'IP', 'Status'])
                for log in logs:
                    writer.writerow([
                        log.performed_at,
                        log.user.username if log.user else "System",
                        log.action_type,
                        log.user_ip,
                        log.success
                    ])
            
            # Log de l'export automatique
            log_event(
                "AUTO_EXPORT",
                f"Export automatique des logs d'audit: {filename}",
                resource_type="AUDIT_LOGS"
            )
            
            print(f"[*] Export automatique réussi : {filepath}")
            
        except Exception as e:
            log_event(
                "AUTO_EXPORT_FAIL",
                f"Échec de l'export automatique des logs",
                resource_type="AUDIT_LOGS",
                success=False,
                error_message=str(e)
            )

def init_scheduler(app):
    """
    Initialise et configure le scheduler
    À appeler depuis app.py
    """
    from src.extensions import scheduler
    
    scheduler.init_app(app)
    scheduler.start()
    
    # Planification : chaque jour à 23h59
    scheduler.add_job(
        id='daily_export',
        func=auto_export_logs,
        trigger='cron',
        hour=23,
        minute=59,
        name='Export quotidien des logs d\'audit'
    )
    
    print("[SCHEDULER] Tâches planifiées initialisées")
    print("[SCHEDULER] Export quotidien des logs à 23:59")