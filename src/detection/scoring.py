"""
Moteur de scoring pour ACRA SOC
Calcul du score de risque selon la formule : 
Score = (0.40×IA) + (0.30×UEBA) + (0.20×TI) + (0.10×C)
"""
import math
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import logging

from src.core.event_bus import bus
from src.models import NetworkFlow, NetworkAsset, Alert, ThreatIntelligence
from src.detection.ti_client import get_ti_client
from src.detection.signatures import get_signature_engine
from src.extensions import db

class ScoringEngine:
    """
    Moteur de calcul du score de risque
    Combine plusieurs sources pour déterminer la criticité d'un flux
    """
    
    # Seuils de sévérité (conformément au CDC)
    SEVERITY_THRESHOLDS = {
        'P1': 80,  # Critique
        'P2': 50,  # Majeure
        'P3': 25,  # Mineure
        'P4': 10,  # Info
        'P5': 0    # Normal
    }
    
    # Poids des composantes (conformément au CDC)
    WEIGHTS = {
        'ml': 0.40,      # Machine Learning
        'ueba': 0.30,    # UEBA / Comportement
        'ti': 0.20,      # Threat Intelligence
        'context': 0.10  # Contexte (actif critique, etc.)
    }
    
    def __init__(self, app=None):
        self.app = app
        self.ti_client = get_ti_client()
        self.signature_engine = get_signature_engine()
        
        # Cache pour les scores d'assets
        self.asset_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Statistiques
        self.stats = {
            'total_scored': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
    
    def _get_asset_context(self, ip: str) -> Dict:
        """
        Récupère le contexte d'un asset (criticité, historique, etc.)
        """
        now = datetime.now()
        
        # Vérifier le cache
        if ip in self.asset_cache:
            cached_time, context = self.asset_cache[ip]
            if (now - cached_time).total_seconds() < self.cache_ttl:
                return context
        
        with self.app.app_context():
            asset = NetworkAsset.query.filter_by(ip_address=ip).first()
            
            if not asset:
                context = {
                    'is_critical': False,
                    'device_type': 'unknown',
                    'avg_traffic_mb': 0,
                    'avg_conn_count': 0,
                    'historical_scores': []
                }
            else:
                context = {
                    'is_critical': asset.is_critical_asset,
                    'device_type': asset.device_type,
                    'avg_traffic_mb': asset.avg_traffic_mb,
                    'avg_conn_count': asset.avg_conn_count,
                    'historical_scores': []  # Sera rempli plus tard
                }
                
                # Récupérer les scores historiques
                recent_alerts = Alert.query.filter(
                    Alert.source_ip == ip,
                    Alert.detected_at > now - timedelta(hours=24)
                ).order_by(Alert.detected_at.desc()).limit(10).all()
                
                for alert in recent_alerts:
                    context['historical_scores'].append({
                        'score': alert.risk_score,
                        'time': alert.detected_at.isoformat(),
                        'category': alert.category.value if alert.category else None
                    })
            
            # Mettre en cache
            self.asset_cache[ip] = (now, context)
            
            return context
    
    def calculate_ml_score(self, flow: NetworkFlow) -> int:
        """
        Calcule le score ML (anomalie statistique)
        À implémenter avec des modèles ML réels dans l'itération 3
        Pour l'instant, simulation basée sur des heuristiques
        """
        score = 0
        
        # Heuristique 1: Volume anormal
        if flow.orig_bytes and flow.orig_bytes > 10_000_000:  # > 10MB
            score += 30
        elif flow.orig_bytes and flow.orig_bytes > 1_000_000:  # > 1MB
            score += 15
        
        # Heuristique 2: Durée anormale
        if flow.duration and flow.duration > 300:  # > 5 minutes
            score += 20
        elif flow.duration and flow.duration > 60:  # > 1 minute
            score += 10
        
        # Heuristique 3: Protocole/service inhabituel
        unusual_services = ['telnet', 'ftp', 'smb', 'netbios']
        if flow.service and flow.service.lower() in unusual_services:
            score += 25
        
        # Heuristique 4: Ports inhabituels
        unusual_ports = [23, 21, 445, 139, 1433, 3306, 5432]
        if flow.dest_port in unusual_ports:
            score += 20
        
        # Normaliser à 0-100
        return min(score, 100)
    
    def calculate_ueba_score(self, flow: NetworkFlow, src_context: Dict, dst_context: Dict) -> int:
        """
        Calcule le score UEBA (écart comportemental)
        Compare le flux au profil habituel de l'asset
        """
        score = 0
        
        # 1. Heure inhabituelle
        hour = datetime.now().hour
        if hour < 6 or hour > 22:  # Nuit
            score += 20
        
        # 2. Volume inhabituel par rapport à la moyenne
        if src_context['avg_traffic_mb'] > 0:
            current_mb = (flow.orig_bytes or 0) / (1024 * 1024)
            ratio = current_mb / src_context['avg_traffic_mb']
            
            if ratio > 10:  # 10x plus que la normale
                score += 30
            elif ratio > 5:
                score += 20
            elif ratio > 2:
                score += 10
        
        # 3. Destination inhabituelle
        if dst_context['device_type'] == 'external' and src_context['device_type'] == 'computer':
            # PC qui parle à l'extérieur (normal mais à surveiller)
            score += 10
        
        # 4. Connexions multiples (potentiel scan)
        if src_context['avg_conn_count'] > 0:
            # À implémenter avec un compteur de connexions récentes
            pass
        
        # 5. Score basé sur l'historique
        if src_context['historical_scores']:
            avg_historical = sum(s['score'] for s in src_context['historical_scores']) / len(src_context['historical_scores'])
            if avg_historical > 50:
                score += 15
        
        return min(score, 100)
    
    def calculate_ti_score(self, flow: NetworkFlow) -> int:
        """
        Calcule le score Threat Intelligence
        Interroge les bases de réputation pour les IPs externes
        """
        if not flow.dest_is_internal:
            # C'est une IP externe, on vérifie sa réputation
            ti_score = self.ti_client.get_threat_score(flow.dest_ip)
            
            # Règle du coupe-circuit (TI ≥ 80)
            if ti_score >= 80:
                self.logger.warning(f"🚨 COUPE-CIRCUIT: TI={ti_score} pour {flow.dest_ip}")
                
            return ti_score
        
        return 0
    
    def calculate_context_score(self, flow: NetworkFlow, src_context: Dict, dst_context: Dict) -> int:
        """
        Calcule le score de contexte (importance de la cible)
        """
        score = 0
        
        # 1. Actif critique (vital)
        if dst_context['is_critical']:
            score += 40
        elif src_context['is_critical']:
            score += 20
        
        # 2. Type d'actif
        critical_types = ['server', 'router', 'firewall']
        if dst_context['device_type'] in critical_types:
            score += 30
        elif src_context['device_type'] in critical_types:
            score += 15
        
        # 3. Ports sensibles
        sensitive_ports = [443, 8443, 22, 3389, 3306, 5432, 27017]
        if flow.dest_port in sensitive_ports:
            score += 20
        
        # 4. Protocoles sensibles
        sensitive_protocols = ['ssh', 'https', 'mysql', 'postgresql', 'mongodb']
        if flow.service and flow.service.lower() in sensitive_protocols:
            score += 10
        
        # 5. Historique d'alertes sur la destination
        if dst_context['historical_scores']:
            recent_critical = any(s['score'] >= 80 for s in dst_context['historical_scores'][:5])
            if recent_critical:
                score += 25
        
        return min(score, 100)
    
    def calculate_risk_score(self, flow: NetworkFlow, 
                            ml_score: int = None, 
                            ueba_score: int = None,
                            ti_score: int = None,
                            context_score: int = None) -> Dict[str, Any]:
        """
        Calcule le score de risque final selon la formule pondérée
        
        Args:
            flow: Le flux réseau à évaluer
            ml_score: Score ML (si None, sera calculé)
            ueba_score: Score UEBA (si None, sera calculé)
            ti_score: Score TI (si None, sera calculé)
            context_score: Score contexte (si None, sera calculé)
        
        Returns:
            Dict contenant les scores individuels et le score final
        """
        # Récupérer le contexte des assets
        src_context = self._get_asset_context(flow.source_ip)
        dst_context = self._get_asset_context(flow.dest_ip)
        
        # Calculer les scores si non fournis
        ml = ml_score if ml_score is not None else self.calculate_ml_score(flow)
        ueba = ueba_score if ueba_score is not None else self.calculate_ueba_score(flow, src_context, dst_context)
        ti = ti_score if ti_score is not None else self.calculate_ti_score(flow)
        context = context_score if context_score is not None else self.calculate_context_score(flow, src_context, dst_context)
        
        # RÈGLE 1: Coupe-circuit (signature critique ou TI ≥ 80)
        # Vérifier d'abord si une signature a matché
        signature_match = self.signature_engine.analyze_flow(flow)
        if signature_match:
            self.logger.info(f"⚡ Coupe-circuit par signature: {signature_match.get('description', '')}")
            return {
                'ml': ml,
                'ueba': ueba,
                'ti': ti,
                'context': context,
                'final': 100,  # Score forcé à 100
                'severity': 'P1',
                'reason': 'signature_match',
                'signature': signature_match
            }
        
        # Vérifier le score TI
        if ti >= 80:
            self.logger.info(f"⚡ Coupe-circuit par TI: {ti} pour {flow.dest_ip}")
            return {
                'ml': ml,
                'ueba': ueba,
                'ti': ti,
                'context': context,
                'final': 100,  # Score forcé à 100
                'severity': 'P1',
                'reason': 'ti_critical'
            }
        
        # RÈGLE 2: Calcul pondéré normal
        final_score = (
            self.WEIGHTS['ml'] * ml +
            self.WEIGHTS['ueba'] * ueba +
            self.WEIGHTS['ti'] * ti +
            self.WEIGHTS['context'] * context
        )
        
        # Arrondir à l'entier
        final_score = int(round(final_score))
        
        # Déterminer la sévérité
        severity = self._get_severity(final_score)
        
        # Mettre à jour les statistiques
        self._update_stats(severity)
        
        self.logger.debug(
            f"Score {final_score} ({severity}) | "
            f"ML={ml}, UEBA={ueba}, TI={ti}, Ctx={context}"
        )
        
        return {
            'ml': ml,
            'ueba': ueba,
            'ti': ti,
            'context': context,
            'final': final_score,
            'severity': severity,
            'reason': 'normal'
        }
    
    def _get_severity(self, score: int) -> str:
        """
        Détermine la sévérité en fonction du score
        """
        if score >= self.SEVERITY_THRESHOLDS['P1']:
            return 'P1'
        elif score >= self.SEVERITY_THRESHOLDS['P2']:
            return 'P2'
        elif score >= self.SEVERITY_THRESHOLDS['P3']:
            return 'P3'
        elif score >= self.SEVERITY_THRESHOLDS['P4']:
            return 'P4'
        else:
            return 'P5'
    
    def _update_stats(self, severity: str):
        """
        Met à jour les statistiques
        """
        self.stats['total_scored'] += 1
        
        if severity == 'P1':
            self.stats['critical'] += 1
        elif severity == 'P2':
            self.stats['high'] += 1
        elif severity == 'P3':
            self.stats['medium'] += 1
        elif severity == 'P4':
            self.stats['low'] += 1
        else:
            self.stats['info'] += 1
    
    def evaluate_flow(self, flow: NetworkFlow) -> Optional[Dict]:
        """
        Évalue complètement un flux et retourne une alerte si nécessaire
        """
        # Calculer le score
        score_result = self.calculate_risk_score(flow)
        
        # Si score suffisamment élevé, créer une alerte
        if score_result['final'] >= self.SEVERITY_THRESHOLDS['P4']:  # Au moins P4
            alert_data = self._create_alert(flow, score_result)
            
            # Publier l'événement
            bus.publish('new_alert', {
                'flow_uid': flow.uid,
                'score': score_result['final'],
                'severity': score_result['severity'],
                'reason': score_result['reason']
            })
            
            return alert_data
        
        return None
    
    def _create_alert(self, flow: NetworkFlow, score_result: Dict) -> Dict:
        """
        Crée une alerte à partir du résultat du scoring
        """
        # Si c'est un coupe-circuit par signature, on a déjà les données
        if score_result.get('signature'):
            return score_result['signature']
        
        # Déterminer la catégorie
        if score_result['reason'] == 'ti_critical':
            category = 'threat_intel'
        elif score_result['ml'] > 70:
            category = 'anomaly'
        elif score_result['ueba'] > 70:
            category = 'ueba'
        else:
            category = 'other'
        
        return {
            'ti_score': score_result['ti'],
            'ml_score': score_result['ml'],
            'ueba_score': score_result['ueba'],
            'context_score': score_result['context'],
            'risk_score': score_result['final'],
            'severity': score_result['severity'],
            'category': category,
            'detection_source': 'scoring',
            'source_ip': flow.source_ip,
            'source_port': flow.source_port,
            'destination_ip': flow.dest_ip,
            'destination_port': flow.dest_port,
            'protocol': flow.protocol,
            'flow_id': flow.id,
            'description': f"Anomalie détectée - Score {score_result['final']}",
            'raw_data': {
                'scores': score_result,
                'flow_uid': flow.uid,
                'orig_bytes': flow.orig_bytes,
                'resp_bytes': flow.resp_bytes,
                'duration': flow.duration
            },
            'evidence': [
                f"Score ML: {score_result['ml']}",
                f"Score UEBA: {score_result['ueba']}",
                f"Score TI: {score_result['ti']}",
                f"Score Contexte: {score_result['context']}"
            ]
        }
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques du moteur"""
        return self.stats.copy()


# Instance singleton
scoring_engine = None

def init_scoring_engine(app):
    """Initialise le moteur de scoring"""
    global scoring_engine
    scoring_engine = ScoringEngine(app)
    return scoring_engine

def get_scoring_engine():
    """Récupère l'instance du moteur de scoring"""
    return scoring_engine