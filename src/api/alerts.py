"""
API REST pour la gestion des alertes
Endpoints pour la consultation, investigation et gestion des alertes (UC15)
"""
from flask import Blueprint, jsonify, request, current_app, render_template  # ← AJOUTER render_template
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json

from src.extensions import db
from src.models import Alert, AlertStatus, AlertSeverity, AlertCategory, Investigation
from src.auth.decorators import role_required
from src.auth.audit_logger import log_event

# ==========================================================
# BLUEPRINT POUR LES PAGES HTML (sans préfixe /api)
# ==========================================================
alerts_html_bp = Blueprint('alerts_html', __name__)

@alerts_html_bp.route('/alerts/list')
@login_required
def list_alerts():
    """Page HTML de la liste des alertes"""
    return render_template('alerts/list.html')

@alerts_html_bp.route('/alerts/<int:alert_id>')
@login_required
def alert_detail(alert_id):
    """Page HTML de détail d'une alerte"""
    return render_template('alerts/detail.html', alert_id=alert_id)

# ==========================================================
# BLUEPRINT POUR L'API REST (avec préfixe /api/alerts)
# ==========================================================
alerts_bp = Blueprint('alerts', __name__, url_prefix='/api/alerts')

# ==========================================================
# ENDPOINTS DE CONSULTATION
# ==========================================================

@alerts_bp.route('', methods=['GET'])
@login_required
def get_alerts():
    """
    Récupère la liste des alertes avec filtres optionnels
    """
    try:
        # Construction de la requête
        query = Alert.query

        # Filtres
        status = request.args.get('status')
        if status:
            query = query.filter(Alert.status == AlertStatus[status.upper()])

        severity = request.args.get('severity')
        if severity:
            query = query.filter(Alert.severity == AlertSeverity[severity.upper()])

        category = request.args.get('category')
        if category:
            query = query.filter(Alert.category == AlertCategory[category.upper()])

        source_ip = request.args.get('source_ip')
        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)

        dest_ip = request.args.get('dest_ip')
        if dest_ip:
            query = query.filter(Alert.destination_ip == dest_ip)

        from_date = request.args.get('from_date')
        if from_date:
            query = query.filter(Alert.detected_at >= datetime.fromisoformat(from_date))

        to_date = request.args.get('to_date')
        if to_date:
            query = query.filter(Alert.detected_at <= datetime.fromisoformat(to_date))

        # Recherche textuelle
        search = request.args.get('search')
        if search:
            query = query.filter(
                db.or_(
                    Alert.description.ilike(f'%{search}%'),
                    Alert.source_ip.ilike(f'%{search}%'),
                    Alert.destination_ip.ilike(f'%{search}%')
                )
            )

        # Tri et pagination
        order_by = request.args.get('order_by', 'detected_at')
        order_dir = request.args.get('order_dir', 'desc')
        
        if order_dir == 'desc':
            query = query.order_by(db.desc(getattr(Alert, order_by)))
        else:
            query = query.order_by(db.asc(getattr(Alert, order_by)))

        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))

        total = query.count()
        alerts = query.offset(offset).limit(limit).all()

        return jsonify({
            'status': 'success',
            'total': total,
            'offset': offset,
            'limit': limit,
            'alerts': [alert.to_dict() for alert in alerts]
        })

    except Exception as e:
        current_app.logger.error(f"Erreur récupération alertes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@alerts_bp.route('/<int:alert_id>', methods=['GET'])
@login_required
def get_alert(alert_id):
    """
    Récupère les détails complets d'une alerte
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({
                'status': 'error',
                'message': f'Alerte {alert_id} non trouvée'
            }), 404

        # Récupérer les alertes connexes (même IP source ou destination)
        related_alerts = Alert.query.filter(
            db.or_(
                Alert.source_ip == alert.source_ip,
                Alert.destination_ip == alert.destination_ip
            ),
            Alert.id != alert.id,
            Alert.detected_at > alert.detected_at - timedelta(hours=24)
        ).order_by(Alert.detected_at.desc()).limit(10).all()

        # Récupérer l'investigation associée
        investigation = Investigation.query.filter_by(alert_id=alert.id).first()

        result = alert.to_dict()
        result['related_alerts'] = [a.to_dict() for a in related_alerts]
        result['investigation'] = investigation.to_dict() if investigation else None

        # Audit
        log_event(
            "ALERT_VIEW",
            f"Consultation de l'alerte {alert.uuid}",
            resource_type="ALERT",
            resource_id=alert.id
        )

        return jsonify({
            'status': 'success',
            'alert': result
        })

    except Exception as e:
        current_app.logger.error(f"Erreur récupération alerte {alert_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@alerts_bp.route('/stats', methods=['GET'])
@login_required
def get_alert_stats():
    """
    Récupère les statistiques des alertes pour le dashboard
    """
    try:
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)

        # Statistiques générales
        total = Alert.query.count()
        open_count = Alert.query.filter(Alert.status == AlertStatus.NEW).count()
        in_progress = Alert.query.filter(Alert.status == AlertStatus.IN_PROGRESS).count()
        resolved = Alert.query.filter(Alert.status == AlertStatus.RESOLVED).count()

        # Par sévérité
        severity_stats = {}
        for severity in AlertSeverity:
            count = Alert.query.filter(Alert.severity == severity).count()
            if count > 0:
                severity_stats[severity.value] = count

        # Évolution temporelle
        today = Alert.query.filter(Alert.detected_at >= today_start).count()
        this_week = Alert.query.filter(Alert.detected_at >= week_ago).count()
        this_month = Alert.query.filter(Alert.detected_at >= month_ago).count()

        # Top IPs sources
        top_sources = db.session.query(
            Alert.source_ip, db.func.count(Alert.id).label('count')
        ).group_by(Alert.source_ip).order_by(db.desc('count')).limit(10).all()

        # Top catégories
        top_categories = db.session.query(
            Alert.category, db.func.count(Alert.id).label('count')
        ).group_by(Alert.category).order_by(db.desc('count')).limit(10).all()

        return jsonify({
            'status': 'success',
            'stats': {
                'total': total,
                'open': open_count,
                'in_progress': in_progress,
                'resolved': resolved,
                'by_severity': severity_stats,
                'timeline': {
                    'today': today,
                    'week': this_week,
                    'month': this_month
                },
                'top_sources': [
                    {'ip': ip, 'count': count} for ip, count in top_sources
                ],
                'top_categories': [
                    {'category': cat.value if hasattr(cat, 'value') else cat, 'count': count}
                    for cat, count in top_categories
                ]
            }
        })

    except Exception as e:
        current_app.logger.error(f"Erreur stats alertes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ==========================================================
# ENDPOINTS DE GESTION
# ==========================================================

@alerts_bp.route('/<int:alert_id>/status', methods=['PUT'])
@login_required
def update_alert_status(alert_id):
    """
    Met à jour le statut d'une alerte
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({
                'status': 'error',
                'message': f'Alerte {alert_id} non trouvée'
            }), 404

        data = request.get_json()
        new_status = data.get('status')
        comment = data.get('comment', '')

        if not new_status:
            return jsonify({
                'status': 'error',
                'message': 'Statut requis'
            }), 400

        old_status = alert.status.value if alert.status else None
        alert.status = AlertStatus[new_status.upper()]
        alert.analyst_comment = comment
        alert.analyst_id = current_user.id

        if new_status.upper() in ['RESOLVED', 'FALSE_POSITIVE']:
            alert.resolved_at = datetime.utcnow()

        db.session.commit()

        # Audit
        log_event(
            "ALERT_STATUS_CHANGE",
            f"Changement de statut: {old_status} -> {new_status}",
            resource_type="ALERT",
            resource_id=alert.id,
            user_id=current_user.id
        )

        return jsonify({
            'status': 'success',
            'message': 'Statut mis à jour',
            'alert': alert.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erreur mise à jour alerte {alert_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@alerts_bp.route('/<int:alert_id>/feedback', methods=['POST'])
@login_required
@role_required('analyst_senior')
def provide_feedback(alert_id):
    """
    Fournit un feedback sur une alerte (TP/FP) pour améliorer les modèles ML
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({
                'status': 'error',
                'message': f'Alerte {alert_id} non trouvée'
            }), 404

        data = request.get_json()
        is_tp = data.get('is_true_positive')
        comment = data.get('comment', '')

        if is_tp is None:
            return jsonify({
                'status': 'error',
                'message': 'Feedback requis (true/false)'
            }), 400

        alert.analyst_feedback = is_tp
        alert.analyst_comment = comment
        alert.analyst_id = current_user.id
        alert.status = AlertStatus.RESOLVED if is_tp else AlertStatus.FALSE_POSITIVE
        alert.resolved_at = datetime.utcnow()

        db.session.commit()

        # Publier l'événement pour le ML
        from src.core.event_bus import bus
        bus.publish('analyst_feedback', {
            'alert_id': alert.id,
            'is_true_positive': is_tp,
            'scores': {
                'ti': alert.ti_score,
                'ml': alert.ml_score,
                'ueba': alert.ueba_score,
                'context': alert.context_score,
                'total': alert.risk_score
            }
        })

        # Audit
        log_event(
            "ALERT_FEEDBACK",
            f"Feedback: {'TP' if is_tp else 'FP'} - {comment}",
            resource_type="ALERT",
            resource_id=alert.id,
            user_id=current_user.id
        )

        return jsonify({
            'status': 'success',
            'message': 'Feedback enregistré'
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erreur feedback alerte {alert_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@alerts_bp.route('/<int:alert_id>/investigation', methods=['POST'])
@login_required
@role_required('analyst_senior')
def start_investigation(alert_id):
    """
    Démarre une investigation sur une alerte
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({
                'status': 'error',
                'message': f'Alerte {alert_id} non trouvée'
            }), 404

        # Vérifier si une investigation existe déjà
        existing = Investigation.query.filter_by(alert_id=alert_id).first()
        if existing:
            return jsonify({
                'status': 'error',
                'message': 'Une investigation existe déjà pour cette alerte'
            }), 400

        data = request.get_json()
        name = data.get('name', f"Investigation - Alerte {alert.uuid[:8]}")
        description = data.get('description', '')

        investigation = Investigation(
            name=name,
            description=description,
            alert_id=alert.id,
            analyst_id=current_user.id,
            status='open',
            priority=data.get('priority', 3)
        )

        db.session.add(investigation)
        alert.status = AlertStatus.IN_PROGRESS
        db.session.commit()

        # Audit
        log_event(
            "INVESTIGATION_START",
            f"Début investigation pour alerte {alert.uuid}",
            resource_type="INVESTIGATION",
            resource_id=investigation.id,
            user_id=current_user.id
        )

        return jsonify({
            'status': 'success',
            'message': 'Investigation créée',
            'investigation': {
                'id': investigation.id,
                'uuid': investigation.uuid,
                'name': investigation.name
            }
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erreur création investigation: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@alerts_bp.route('/bulk', methods=['POST'])
@login_required
@role_required('analyst_senior')
def bulk_operation():
    """
    Opérations groupées sur plusieurs alertes
    """
    try:
        data = request.get_json()
        alert_ids = data.get('alert_ids', [])
        operation = data.get('operation')
        value = data.get('value')

        if not alert_ids or not operation:
            return jsonify({
                'status': 'error',
                'message': 'IDs et opération requis'
            }), 400

        alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all()
        count = len(alerts)

        if operation == 'status':
            for alert in alerts:
                alert.status = AlertStatus[value.upper()]
                alert.analyst_id = current_user.id
                if value.upper() in ['RESOLVED', 'FALSE_POSITIVE']:
                    alert.resolved_at = datetime.utcnow()

        elif operation == 'assign':
            # Assigner à un analyste
            user_id = value
            for alert in alerts:
                alert.analyst_id = user_id

        elif operation == 'delete':
            for alert in alerts:
                db.session.delete(alert)

        db.session.commit()

        # Audit
        log_event(
            "ALERT_BULK_OPERATION",
            f"Opération groupée {operation} sur {count} alertes",
            resource_type="ALERT",
            user_id=current_user.id
        )

        return jsonify({
            'status': 'success',
            'message': f'Opération {operation} effectuée sur {count} alertes'
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erreur opération groupée: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ==========================================================
# ENDPOINTS POUR LE DASHBOARD (simplifiés)
# ==========================================================

@alerts_bp.route('/dashboard/recent', methods=['GET'])
@login_required
def get_recent_alerts():
    """
    Récupère les alertes récentes pour le dashboard principal
    """
    try:
        limit = min(int(request.args.get('limit', 10)), 50)
        
        alerts = Alert.query.filter(
            Alert.status.in_([AlertStatus.NEW, AlertStatus.IN_PROGRESS])
        ).order_by(
            Alert.detected_at.desc()
        ).limit(limit).all()

        return jsonify({
            'status': 'success',
            'alerts': [{
                'id': a.id,
                'uuid': a.uuid[:8],
                'severity': a.severity.value if a.severity else 'P5',
                'risk_score': a.risk_score,
                'source_ip': a.source_ip,
                'destination_ip': a.destination_ip,
                'category': a.category.value if a.category else 'other',
                'detected_at': a.detected_at.isoformat(),
                'description': a.description or 'Alerte détectée'
            } for a in alerts]
        })

    except Exception as e:
        current_app.logger.error(f"Erreur récupération alertes récentes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@alerts_bp.route('/dashboard/timeline', methods=['GET'])
@login_required
def get_alert_timeline():
    """
    Récupère la timeline des alertes pour les graphiques
    """
    try:
        days = int(request.args.get('days', 7))
        start_date = datetime.utcnow() - timedelta(days=days)

        # Grouper par jour
        from sqlalchemy import func, cast, Date
        
        timeline = db.session.query(
            cast(Alert.detected_at, Date).label('date'),
            func.count(Alert.id).label('count'),
            func.sum(case([(Alert.severity == 'P1', 1)], else_=0)).label('p1'),
            func.sum(case([(Alert.severity == 'P2', 1)], else_=0)).label('p2'),
            func.sum(case([(Alert.severity == 'P3', 1)], else_=0)).label('p3')
        ).filter(
            Alert.detected_at >= start_date
        ).group_by(
            cast(Alert.detected_at, Date)
        ).order_by(
            cast(Alert.detected_at, Date)
        ).all()

        return jsonify({
            'status': 'success',
            'timeline': [{
                'date': str(t.date),
                'total': t.count,
                'p1': t.p1,
                'p2': t.p2,
                'p3': t.p3
            } for t in timeline]
        })

    except Exception as e:
        current_app.logger.error(f"Erreur timeline alertes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ==========================================================
# ENDPOINTS POUR LA CONFIGURATION
# ==========================================================

@alerts_bp.route('/config/categories', methods=['GET'])
@login_required
def get_categories():
    """Retourne la liste des catégories d'alertes disponibles"""
    return jsonify({
        'status': 'success',
        'categories': [c.value for c in AlertCategory]
    })


@alerts_bp.route('/config/severities', methods=['GET'])
@login_required
def get_severities():
    """Retourne la liste des sévérités disponibles"""
    return jsonify({
        'status': 'success',
        'severities': [s.value for s in AlertSeverity]
    })


@alerts_bp.route('/config/statuses', methods=['GET'])
@login_required
def get_statuses():
    """Retourne la liste des statuts disponibles"""
    return jsonify({
        'status': 'success',
        'statuses': [s.value for s in AlertStatus]
    })