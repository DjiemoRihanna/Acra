"""
Moteur de signatures pour ACRA SOC
Détection basée sur des patterns (règles Suricata/Snort)
"""

import logging
import json
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import threading

from src.core.event_bus import bus
from src.models import DetectionRule, Alert, AlertSeverity, AlertCategory, NetworkFlow
from src.extensions import db

class SignatureEngine:
    """
    Moteur de détection par signatures
    Analyse les flux réseau et les compare à des règles
    """
    
    def __init__(self, app=None):
        self.app = app
        self.rules = []  # Cache des règles actives
        self.rules_last_update = 0
        self.rules_update_interval = 300  # 5 minutes
        self.rules_lock = threading.Lock()
        
        # Statistiques
        self.stats = {
            'rules_loaded': 0,
            'matches': 0,
            'errors': 0,
            'last_match': None
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def _load_rules(self, force: bool = False):
        """Charge les règles depuis la base de données"""
        now = time.time()
        if not force and now - self.rules_last_update < self.rules_update_interval:
            return
        
        with self.app.app_context():
            with self.rules_lock:
                try:
                    rules = DetectionRule.query.filter_by(
                        is_enabled=True,
                        rule_type='signature'
                    ).all()
                    
                    self.rules = []
                    for rule in rules:
                        # Compiler la logique pour une recherche plus rapide
                        compiled = self._compile_rule(rule)
                        if compiled:
                            self.rules.append({
                                'id': rule.id,
                                'name': rule.name,
                                'severity': rule.severity,
                                'category': rule.category,
                                'priority': rule.priority,
                                'logic': rule.logic,
                                'compiled': compiled
                            })
                    
                    self.rules_last_update = now
                    self.stats['rules_loaded'] = len(self.rules)
                    self.logger.info(f"✅ {len(self.rules)} règles de signature chargées")
                    
                except Exception as e:
                    self.logger.error(f"❌ Erreur chargement règles: {e}")
    
    def _compile_rule(self, rule: DetectionRule) -> Optional[Dict]:
        """
        Compile une règle pour une recherche plus rapide
        Retourne un dictionnaire avec des patterns pré-compilés
        """
        logic = rule.logic
        compiled = {}
        
        try:
            # Compiler les patterns regex
            if 'pattern' in logic:
                compiled['pattern_re'] = re.compile(logic['pattern'], re.IGNORECASE)
            
            if 'patterns' in logic:
                compiled['patterns_re'] = [
                    re.compile(p, re.IGNORECASE) for p in logic['patterns']
                ]
            
            # Champs à vérifier
            compiled['fields'] = logic.get('fields', [])
            
            # Conditions
            compiled['conditions'] = logic.get('conditions', {})
            
            return compiled
            
        except Exception as e:
            self.logger.error(f"Erreur compilation règle {rule.id}: {e}")
            return None
    
    def _check_rule_flow(self, rule: Dict, flow: NetworkFlow) -> Tuple[bool, Dict]:
        """
        Vérifie si un flux correspond à une règle
        Retourne: (match, metadata)
        """
        logic = rule['logic']
        compiled = rule['compiled']
        metadata = {}
        
        # Vérifier les IPs sources
        src_ips = logic.get('source_ips', [])
        if src_ips and flow.source_ip not in src_ips:
            return False, {}
        
        # Vérifier les IPs destinations
        dst_ips = logic.get('destination_ips', [])
        if dst_ips and flow.dest_ip not in dst_ips:
            return False, {}
        
        # Vérifier les ports
        ports = logic.get('ports', [])
        if ports and flow.dest_port not in ports and flow.source_port not in ports:
            return False, {}
        
        # Vérifier les protocoles
        protocols = logic.get('protocols', [])
        if protocols and flow.protocol.lower() not in [p.lower() for p in protocols]:
            return False, {}
        
        # Vérifier les services
        services = logic.get('services', [])
        if services and flow.service not in services:
            return False, {}
        
        # Vérifier les patterns dans les champs
        if compiled.get('pattern_re'):
            for field in compiled.get('fields', []):
                value = getattr(flow, field, None)
                if value and compiled['pattern_re'].search(str(value)):
                    metadata['matched_field'] = field
                    metadata['matched_value'] = value
                    return True, metadata
        
        # Vérifier les patterns multiples
        if compiled.get('patterns_re'):
            matches = []
            for field in compiled.get('fields', []):
                value = getattr(flow, field, None)
                if value:
                    for i, pattern_re in enumerate(compiled['patterns_re']):
                        if pattern_re.search(str(value)):
                            matches.append({
                                'field': field,
                                'pattern_index': i,
                                'value': value[:100]
                            })
            
            if matches:
                metadata['matches'] = matches
                return True, metadata
        
        # Vérifier les conditions personnalisées
        conditions = compiled.get('conditions', {})
        if conditions:
            # Conditions simples
            if 'orig_bytes >' in conditions:
                threshold = int(conditions['orig_bytes >'])
                if flow.orig_bytes and flow.orig_bytes > threshold:
                    metadata['condition'] = f"orig_bytes > {threshold}"
                    return True, metadata
            
            if 'resp_bytes >' in conditions:
                threshold = int(conditions['resp_bytes >'])
                if flow.resp_bytes and flow.resp_bytes > threshold:
                    metadata['condition'] = f"resp_bytes > {threshold}"
                    return True, metadata
            
            if 'duration >' in conditions:
                threshold = float(conditions['duration >'])
                if flow.duration and flow.duration > threshold:
                    metadata['condition'] = f"duration > {threshold}"
                    return True, metadata
        
        return False, {}
    
    def analyze_flow(self, flow: NetworkFlow) -> Optional[Dict]:
        """
        Analyse un flux réseau et retourne une alerte si correspondance
        """
        # Charger les règles si nécessaire
        self._load_rules()
        
        if not self.rules:
            return None
        
        # Vérifier chaque règle
        for rule in self.rules:
            try:
                match, metadata = self._check_rule_flow(rule, flow)
                
                if match:
                    self.stats['matches'] += 1
                    self.stats['last_match'] = datetime.now().isoformat()
                    
                    # Créer l'alerte
                    alert_data = self._create_alert(rule, flow, metadata)
                    
                    self.logger.info(f"🎯 Signature match: {rule['name']} sur {flow.source_ip} -> {flow.dest_ip}")
                    
                    # Publier l'événement
                    bus.publish('signature_match', {
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'flow_uid': flow.uid,
                        'source_ip': flow.source_ip,
                        'dest_ip': flow.dest_ip,
                        'metadata': metadata
                    })
                    
                    return alert_data
                    
            except Exception as e:
                self.stats['errors'] += 1
                self.logger.error(f"Erreur analyse règle {rule.get('id')}: {e}")
        
        return None
    
    def _create_alert(self, rule: Dict, flow: NetworkFlow, metadata: Dict) -> Dict:
        """
        Crée une alerte à partir d'une correspondance de règle
        """
        severity_map = {
            0: AlertSeverity.INFO,
            25: AlertSeverity.LOW,
            50: AlertSeverity.MEDIUM,
            75: AlertSeverity.HIGH,
            100: AlertSeverity.CRITICAL
        }
        
        # Déterminer la sévérité
        rule_severity = rule['severity']
        severity = AlertSeverity.MEDIUM
        
        for threshold, sev in severity_map.items():
            if rule_severity >= threshold:
                severity = sev
            else:
                break
        
        # Calculer le score de risque
        # Pour les signatures, le score est élevé (coupe-circuit)
        risk_score = max(rule_severity, 80)  # Au moins 80 pour les signatures
        
        # Description
        description = f"Signature match: {rule['name']}"
        if metadata.get('matched_field'):
            description += f" sur {metadata['matched_field']}: {metadata.get('matched_value', '')}"
        
        return {
            'rule_id': rule['id'],
            'signature_id': f"SIG-{rule['id']}",
            'ti_score': 0,
            'ml_score': 0,
            'ueba_score': 0,
            'context_score': 20,  # Bonus pour signature
            'risk_score': risk_score,
            'severity': severity.value,
            'category': AlertCategory.SIGNATURE.value,
            'detection_source': 'signature',
            'source_ip': flow.source_ip,
            'source_port': flow.source_port,
            'destination_ip': flow.dest_ip,
            'destination_port': flow.dest_port,
            'protocol': flow.protocol,
            'flow_id': flow.id,
            'description': description,
            'raw_data': {
                'rule': rule['name'],
                'metadata': metadata,
                'flow': {
                    'uid': flow.uid,
                    'orig_bytes': flow.orig_bytes,
                    'resp_bytes': flow.resp_bytes,
                    'duration': flow.duration,
                    'service': flow.service
                }
            },
            'evidence': [
                f"Flux {flow.uid}",
                f"Règle: {rule['name']}",
                f"Détails: {json.dumps(metadata)}"
            ]
        }
    
    def add_rule(self, rule_data: Dict) -> int:
        """
        Ajoute une nouvelle règle de signature
        """
        with self.app.app_context():
            rule = DetectionRule(
                name=rule_data['name'],
                description=rule_data.get('description', ''),
                rule_type='signature',
                logic=rule_data['logic'],
                severity=rule_data.get('severity', 50),
                category=rule_data.get('category', 'other'),
                source_ips=rule_data.get('source_ips', []),
                destination_ips=rule_data.get('destination_ips', []),
                protocols=rule_data.get('protocols', []),
                ports=rule_data.get('ports', []),
                is_enabled=rule_data.get('is_enabled', True),
                priority=rule_data.get('priority', 5),
                tags=rule_data.get('tags', [])
            )
            
            db.session.add(rule)
            db.session.commit()
            
            # Forcer le rechargement des règles
            self._load_rules(force=True)
            
            self.logger.info(f"➕ Nouvelle règle ajoutée: {rule.name}")
            
            # Publier l'événement
            bus.publish('rule_updated', {
                'action': 'add',
                'rule_id': rule.id,
                'rule_name': rule.name
            })
            
            return rule.id
    
    def update_rule(self, rule_id: int, rule_data: Dict) -> bool:
        """
        Met à jour une règle existante
        """
        with self.app.app_context():
            rule = DetectionRule.query.get(rule_id)
            if not rule:
                return False
            
            for key, value in rule_data.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            
            rule.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Forcer le rechargement des règles
            self._load_rules(force=True)
            
            self.logger.info(f"📝 Règle mise à jour: {rule.name}")
            
            # Publier l'événement
            bus.publish('rule_updated', {
                'action': 'update',
                'rule_id': rule.id,
                'rule_name': rule.name
            })
            
            return True
    
    def delete_rule(self, rule_id: int) -> bool:
        """
        Supprime une règle
        """
        with self.app.app_context():
            rule = DetectionRule.query.get(rule_id)
            if not rule:
                return False
            
            rule_name = rule.name
            db.session.delete(rule)
            db.session.commit()
            
            # Forcer le rechargement des règles
            self._load_rules(force=True)
            
            self.logger.info(f"🗑️ Règle supprimée: {rule_name}")
            
            # Publier l'événement
            bus.publish('rule_updated', {
                'action': 'delete',
                'rule_id': rule_id,
                'rule_name': rule_name
            })
            
            return True
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques du moteur"""
        return {
            'rules_loaded': self.stats['rules_loaded'],
            'matches': self.stats['matches'],
            'errors': self.stats['errors'],
            'last_match': self.stats['last_match']
        }


# Instance singleton
signature_engine = None

def init_signature_engine(app):
    """Initialise le moteur de signatures"""
    global signature_engine
    signature_engine = SignatureEngine(app)
    return signature_engine

def get_signature_engine():
    """Récupère l'instance du moteur de signatures"""
    return signature_engine