"""
Moteur de corrélation pour ACRA SOC
Détection de patterns complexes et agrégation d'alertes
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, Counter
import threading
import time
import logging

from src.core.event_bus import bus
from src.models import Alert, DetectionRule, AlertSeverity, AlertCategory, NetworkFlow
from src.extensions import db

class CorrelationEngine:
    """
    Moteur de corrélation d'événements
    Détecte des patterns complexes et agrège les alertes connexes
    """
    
    # Fenêtres temporelles pour la corrélation (en secondes)
    TIME_WINDOWS = {
        'short': 60,      # 1 minute
        'medium': 300,    # 5 minutes
        'long': 3600,     # 1 heure
        'day': 86400      # 24 heures
    }
    
    def __init__(self, app=None):
        self.app = app
        self.running = True
        self.thread = None
        
        # Cache des corrélations en mémoire
        self.event_buffer = defaultdict(list)  # IP -> liste d'événements
        self.correlation_cache = {}  # ID -> données de corrélation
        
        # Verrous pour la synchronisation
        self.buffer_lock = threading.Lock()
        self.cache_lock = threading.Lock()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Statistiques
        self.stats = {
            'events_processed': 0,
            'correlations_found': 0,
            'alerts_aggregated': 0,
            'patterns_matched': 0
        }
    
    def start(self):
        """Démarre le thread de corrélation"""
        if self.thread is None or not self.thread.is_alive():
            self.running = True
            self.thread = threading.Thread(target=self._correlation_loop, daemon=True)
            self.thread.start()
            self.logger.info("✅ Moteur de corrélation démarré")
    
    def stop(self):
        """Arrête le thread de corrélation"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.logger.info("🛑 Moteur de corrélation arrêté")
    
    def _correlation_loop(self):
        """Boucle principale de corrélation"""
        while self.running:
            try:
                self._clean_old_events()
                self._run_correlation_rules()
                time.sleep(10)  # Vérification toutes les 10 secondes
            except Exception as e:
                self.logger.error(f"Erreur dans la boucle de corrélation: {e}")
                time.sleep(30)
    
    def _clean_old_events(self):
        """Nettoie les événements plus vieux que la fenêtre maximale"""
        max_age = self.TIME_WINDOWS['day']
        cutoff = datetime.now() - timedelta(seconds=max_age)
        
        with self.buffer_lock:
            for ip in list(self.event_buffer.keys()):
                self.event_buffer[ip] = [
                    e for e in self.event_buffer[ip]
                    if e['timestamp'] > cutoff
                ]
                if not self.event_buffer[ip]:
                    del self.event_buffer[ip]
    
    def add_event(self, event: Dict):
        """
        Ajoute un événement au buffer de corrélation
        """
        event['timestamp'] = datetime.now()
        
        with self.buffer_lock:
            # Indexer par IP source
            src_ip = event.get('source_ip')
            if src_ip:
                self.event_buffer[src_ip].append(event)
            
            # Indexer par IP destination aussi
            dst_ip = event.get('destination_ip')
            if dst_ip and dst_ip != src_ip:
                self.event_buffer[dst_ip].append(event)
        
        self.stats['events_processed'] += 1
    
    def add_alert(self, alert: Alert):
        """
        Ajoute une alerte au buffer de corrélation
        """
        event = {
            'type': 'alert',
            'alert_id': alert.id,
            'source_ip': alert.source_ip,
            'destination_ip': alert.destination_ip,
            'severity': alert.severity.value if alert.severity else None,
            'category': alert.category.value if alert.category else None,
            'risk_score': alert.risk_score,
            'timestamp': alert.detected_at,
            'raw': alert
        }
        self.add_event(event)
    
    def add_flow(self, flow: NetworkFlow):
        """
        Ajoute un flux au buffer de corrélation
        """
        event = {
            'type': 'flow',
            'flow_id': flow.id,
            'source_ip': flow.source_ip,
            'destination_ip': flow.dest_ip,
            'protocol': flow.protocol,
            'port': flow.dest_port,
            'bytes': (flow.orig_bytes or 0) + (flow.resp_bytes or 0),
            'timestamp': flow.ts,
            'raw': flow
        }
        self.add_event(event)
    
    def _run_correlation_rules(self):
        """Exécute les règles de corrélation"""
        with self.app.app_context():
            # Charger les règles de corrélation actives
            rules = DetectionRule.query.filter_by(
                is_enabled=True,
                rule_type='correlation'
            ).all()
            
            for rule in rules:
                try:
                    matches = self._apply_correlation_rule(rule)
                    for match in matches:
                        self._handle_correlation_match(rule, match)
                except Exception as e:
                    self.logger.error(f"Erreur règle {rule.id}: {e}")
    
    def _apply_correlation_rule(self, rule: DetectionRule) -> List[Dict]:
        """
        Applique une règle de corrélation et retourne les correspondances
        """
        logic = rule.logic
        matches = []
        
        # Règle: Même IP source, fenêtre temporelle
        if logic.get('type') == 'same_source':
            window = logic.get('window', 'medium')
            min_count = logic.get('min_count', 5)
            time_window = self.TIME_WINDOWS.get(window, 300)
            
            cutoff = datetime.now() - timedelta(seconds=time_window)
            
            with self.buffer_lock:
                for ip, events in self.event_buffer.items():
                    recent = [e for e in events if e['timestamp'] > cutoff]
                    
                    if len(recent) >= min_count:
                        # Vérifier les filtres supplémentaires
                        if self._check_filters(recent, logic.get('filters', {})):
                            matches.append({
                                'type': 'same_source',
                                'ip': ip,
                                'count': len(recent),
                                'events': recent,
                                'window': window
                            })
        
        # Règle: Même destination, sources multiples
        elif logic.get('type') == 'same_destination':
            window = logic.get('window', 'medium')
            min_sources = logic.get('min_sources', 3)
            time_window = self.TIME_WINDOWS.get(window, 300)
            
            cutoff = datetime.now() - timedelta(seconds=time_window)
            dest_events = defaultdict(list)
            
            with self.buffer_lock:
                for ip, events in self.event_buffer.items():
                    for e in events:
                        if e['timestamp'] > cutoff and e.get('destination_ip'):
                            dest_events[e['destination_ip']].append(e)
            
            for dest_ip, events in dest_events.items():
                unique_sources = set(e['source_ip'] for e in events if e.get('source_ip'))
                
                if len(unique_sources) >= min_sources:
                    matches.append({
                        'type': 'same_destination',
                        'destination_ip': dest_ip,
                        'sources': list(unique_sources),
                        'count': len(events),
                        'window': window
                    })
        
        # Règle: Séquentielle (A puis B)
        elif logic.get('type') == 'sequential':
            pattern = logic.get('pattern', [])
            window = logic.get('window', 'medium')
            time_window = self.TIME_WINDOWS.get(window, 300)
            
            cutoff = datetime.now() - timedelta(seconds=time_window)
            
            # Grouper par IP source
            with self.buffer_lock:
                for ip, events in self.event_buffer.items():
                    recent = sorted(
                        [e for e in events if e['timestamp'] > cutoff],
                        key=lambda x: x['timestamp']
                    )
                    
                    if len(recent) >= len(pattern):
                        # Chercher la séquence
                        sequence = self._find_sequence(recent, pattern)
                        if sequence:
                            matches.append({
                                'type': 'sequential',
                                'ip': ip,
                                'sequence': sequence,
                                'window': window
                            })
        
        return matches
    
    def _check_filters(self, events: List[Dict], filters: Dict) -> bool:
        """
        Vérifie si les événements correspondent aux filtres
        """
        # Filtre par type d'événement
        if 'event_types' in filters:
            types = set(e['type'] for e in events)
            if not any(t in filters['event_types'] for t in types):
                return False
        
        # Filtre par sévérité minimum
        if 'min_severity' in filters:
            severities = [e.get('severity') for e in events if e.get('severity')]
            severity_values = {'P1': 4, 'P2': 3, 'P3': 2, 'P4': 1, 'P5': 0}
            min_val = severity_values.get(filters['min_severity'], 0)
            
            max_seen = max([severity_values.get(s, 0) for s in severities], default=0)
            if max_seen < min_val:
                return False
        
        # Filtre par score minimum
        if 'min_score' in filters:
            scores = [e.get('risk_score', 0) for e in events]
            if max(scores, default=0) < filters['min_score']:
                return False
        
        return True
    
    def _find_sequence(self, events: List[Dict], pattern: List[str]) -> Optional[List[Dict]]:
        """
        Cherche une séquence d'événements correspondant au pattern
        """
        sequence = []
        pattern_idx = 0
        
        for event in events:
            event_type = event.get('type')
            if event_type == pattern[pattern_idx]:
                sequence.append(event)
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    return sequence
        
        return None
    
    def _handle_correlation_match(self, rule: DetectionRule, match: Dict):
        """
        Traite une correspondance de corrélation
        """
        self.stats['correlations_found'] += 1
        
        # Créer une alerte de corrélation
        alert_data = self._create_correlation_alert(rule, match)
        
        # Sauvegarder dans la base
        with self.app.app_context():
            alert = Alert(
                ti_score=alert_data['ti_score'],
                ml_score=alert_data['ml_score'],
                ueba_score=alert_data['ueba_score'],
                context_score=alert_data['context_score'],
                risk_score=alert_data['risk_score'],
                severity=alert_data['severity'],
                category=alert_data['category'],
                detection_source='correlation',
                rule_id=rule.id,
                source_ip=match.get('ip') or match.get('destination_ip', '0.0.0.0'),
                destination_ip=match.get('destination_ip', match.get('ip', '0.0.0.0')),
                description=alert_data['description'],
                raw_data=alert_data['raw_data'],
                evidence=alert_data['evidence']
            )
            
            db.session.add(alert)
            db.session.commit()
            
            self.logger.info(f"🎯 Corrélation: {rule.name} - {alert_data['description']}")
            
            # Publier l'événement
            bus.publish('correlation_match', {
                'rule_id': rule.id,
                'rule_name': rule.name,
                'alert_id': alert.id,
                'match': match
            })
    
    def _create_correlation_alert(self, rule: DetectionRule, match: Dict) -> Dict:
        """
        Crée une alerte à partir d'une corrélation
        """
        # Déterminer la sévérité basée sur la règle
        severity_map = {
            0: 'P5', 25: 'P4', 50: 'P3', 75: 'P2', 100: 'P1'
        }
        severity = 'P3'  # Par défaut
        for threshold, sev in severity_map.items():
            if rule.severity >= threshold:
                severity = sev
        
        # Compter les événements
        event_count = len(match.get('events', []))
        
        # Construire la description
        if match['type'] == 'same_source':
            description = f"{event_count} événements depuis {match['ip']} en {match['window']}"
        elif match['type'] == 'same_destination':
            description = f"{match['count']} événements vers {match['destination_ip']} depuis {len(match['sources'])} sources"
        elif match['type'] == 'sequential':
            description = f"Séquence d'événements détectée pour {match['ip']}"
        else:
            description = f"Corrélation: {rule.name}"
        
        # Collecter les preuves
        evidence = []
        for e in match.get('events', [])[:10]:  # Limiter à 10 preuves
            if e['type'] == 'alert':
                evidence.append(f"Alerte {e.get('alert_id')} - {e.get('category')}")
            elif e['type'] == 'flow':
                evidence.append(f"Flux {e.get('flow_id')} - {e.get('bytes')} bytes")
        
        return {
            'ti_score': 0,
            'ml_score': 0,
            'ueba_score': rule.severity,
            'context_score': 0,
            'risk_score': rule.severity,
            'severity': severity,
            'category': AlertCategory.ANOMALY.value,
            'description': description,
            'raw_data': {
                'rule': rule.name,
                'match_type': match['type'],
                'match_data': {k: v for k, v in match.items() if k not in ['events']}
            },
            'evidence': evidence[:5]  # Garder les 5 premières preuves
        }
    
    def aggregate_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """
        Agrège des alertes similaires pour réduire le bruit
        """
        if len(alerts) < 2:
            return alerts
        
        grouped = defaultdict(list)
        
        # Grouper par (source_ip, destination_ip, category)
        for alert in alerts:
            key = (alert.source_ip, alert.destination_ip, alert.category)
            grouped[key].append(alert)
        
        result = []
        for group in grouped.values():
            if len(group) > 5:  # Seuil d'agrégation
                aggregated = self._aggregate_group(group)
                result.append(aggregated)
                self.stats['alerts_aggregated'] += (len(group) - 1)
            else:
                result.extend(group)
        
        return result
    
    def _aggregate_group(self, alerts: List[Alert]) -> Alert:
        """
        Agrège un groupe d'alertes similaires
        """
        # Prendre l'alerte la plus récente comme base
        base = max(alerts, key=lambda a: a.detected_at)
        
        # Mettre à jour les métadonnées
        base.risk_score = max(a.risk_score for a in alerts)
        base.detection_source = 'aggregated'
        
        # Ajouter les IDs des alertes agrégées
        aggregated_ids = [a.id for a in alerts if a.id != base.id]
        base.raw_data = base.raw_data or {}
        base.raw_data['aggregated_alerts'] = aggregated_ids
        base.raw_data['aggregated_count'] = len(alerts)
        
        # Mettre à jour la description
        base.description = f"Agrégation de {len(alerts)} alertes similaires"
        
        return base
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques du moteur"""
        with self.buffer_lock:
            buffer_size = sum(len(events) for events in self.event_buffer.values())
        
        return {
            **self.stats,
            'buffer_size': buffer_size,
            'unique_ips': len(self.event_buffer)
        }


# Instance singleton
correlation_engine = None

def init_correlation_engine(app):
    """Initialise le moteur de corrélation"""
    global correlation_engine
    correlation_engine = CorrelationEngine(app)
    correlation_engine.start()
    return correlation_engine

def get_correlation_engine():
    """Récupère l'instance du moteur de corrélation"""
    return correlation_engine