"""
Moteur de profilage comportemental (UEBA) pour ACRA SOC
Établit des baselines et détecte les écarts par rapport à la normale
"""
import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import threading
import time
import logging
import json

from src.core.event_bus import bus
from src.models import NetworkAsset, NetworkFlow, Alert
from src.extensions import db

class BaseliningEngine:
    """
    Moteur d'analyse comportementale (UEBA)
    Établit des profils de comportement normal et détecte les anomalies
    """
    
    # Périodes d'apprentissage (en jours)
    LEARNING_PERIODS = {
        'hourly': 7,      # 7 jours pour le profil horaire
        'daily': 30,      # 30 jours pour le profil journalier
        'weekly': 90      # 90 jours pour le profil hebdomadaire
    }
    
    # Facteurs de seuil (nombre d'écarts-types)
    THRESHOLD_FACTORS = {
        'critical': 5.0,   # 5 sigmas - anomalie critique
        'high': 3.0,       # 3 sigmas - anomalie haute
        'medium': 2.0,     # 2 sigmas - anomalie moyenne
        'low': 1.5         # 1.5 sigma - anomalie faible
    }
    
    def __init__(self, app=None):
        self.app = app
        self.running = True
        self.thread = None
        
        # Profils en mémoire {ip: {metric: {hour: stats}}}
        self.profiles = defaultdict(lambda: defaultdict(dict))
        
        # Historique récent pour chaque IP {ip: deque}
        self.recent_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Verrous
        self.profile_lock = threading.Lock()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Statistiques
        self.stats = {
            'assets_profiled': 0,
            'anomalies_detected': 0,
            'profiles_updated': 0,
            'last_learning': None
        }
    
    def start(self):
        """Démarre le thread de profilage"""
        if self.thread is None or not self.thread.is_alive():
            self.running = True
            self.thread = threading.Thread(target=self._baselining_loop, daemon=True)
            self.thread.start()
            self.logger.info("✅ Moteur UEBA démarré")
    
    def stop(self):
        """Arrête le thread de profilage"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.logger.info("🛑 Moteur UEBA arrêté")
    
    def _baselining_loop(self):
        """Boucle principale de mise à jour des profils"""
        while self.running:
            try:
                # Apprentissage profond (toutes les heures)
                now = datetime.now()
                if now.minute == 0:  # Toutes les heures
                    self._update_all_profiles()
                
                # Nettoyage des profils obsolètes
                self._clean_old_profiles()
                
                time.sleep(60)  # Vérification toutes les minutes
                
            except Exception as e:
                self.logger.error(f"Erreur dans la boucle UEBA: {e}")
                time.sleep(300)
    
    def _update_all_profiles(self):
        """Met à jour tous les profils d'assets actifs"""
        with self.app.app_context():
            try:
                # Récupérer les assets actifs
                assets = NetworkAsset.query.filter_by(status='online').all()
                
                updated = 0
                for asset in assets:
                    if self._update_asset_profile(asset):
                        updated += 1
                
                self.stats['profiles_updated'] += updated
                self.stats['last_learning'] = datetime.now().isoformat()
                
                self.logger.info(f"📊 Profils mis à jour pour {updated} assets")
                
            except Exception as e:
                self.logger.error(f"Erreur mise à jour profils: {e}")
    
    def _update_asset_profile(self, asset: NetworkAsset) -> bool:
        """
        Met à jour le profil comportemental d'un asset
        Retourne True si le profil a été modifié
        """
        try:
            # Récupérer l'historique des flux
            end = datetime.utcnow()
            start = end - timedelta(days=30)  # 30 jours d'historique
            
            flows = NetworkFlow.query.filter(
                NetworkFlow.source_ip == asset.ip_address,
                NetworkFlow.ts.between(start, end)
            ).all()
            
            if len(flows) < 10:  # Pas assez de données
                return False
            
            # Calculer les métriques par heure
            hourly_metrics = self._calculate_hourly_metrics(flows)
            
            # Mettre à jour le profil
            with self.profile_lock:
                old_profile = asset.behavioral_profile or {}
                
                new_profile = {
                    'hourly': hourly_metrics,
                    'daily': self._calculate_daily_metrics(flows),
                    'weekly': self._calculate_weekly_metrics(flows),
                    'last_updated': datetime.utcnow().isoformat(),
                    'total_flows': len(flows)
                }
                
                asset.behavioral_profile = new_profile
                asset.last_baseline_update = datetime.utcnow()
                
                # Calculer le score de déviation par rapport à l'ancien profil
                if old_profile:
                    deviation = self._calculate_profile_deviation(old_profile, new_profile)
                    asset.deviation_score = deviation
                
                db.session.commit()
                
                # Mettre à jour le cache mémoire
                self.profiles[asset.ip_address] = new_profile
                
                return True
                
        except Exception as e:
            self.logger.error(f"Erreur pour {asset.ip_address}: {e}")
            return False
    
    def _calculate_hourly_metrics(self, flows: List[NetworkFlow]) -> Dict:
        """
        Calcule les métriques par heure de la journée
        """
        hourly = defaultdict(lambda: {
            'count': 0,
            'bytes': [],
            'duration': [],
            'unique_dests': set()
        })
        
        for flow in flows:
            hour = flow.ts.hour
            hourly[hour]['count'] += 1
            hourly[hour]['bytes'].append((flow.orig_bytes or 0) + (flow.resp_bytes or 0))
            hourly[hour]['duration'].append(flow.duration or 0)
            hourly[hour]['unique_dests'].add(flow.dest_ip)
        
        # Calculer les statistiques
        result = {}
        for hour, data in hourly.items():
            bytes_list = data['bytes']
            duration_list = [d for d in data['duration'] if d > 0]
            
            result[str(hour)] = {
                'avg_count': data['count'] / 30,  # Moyenne sur 30 jours
                'avg_bytes': statistics.mean(bytes_list) if bytes_list else 0,
                'std_bytes': statistics.stdev(bytes_list) if len(bytes_list) > 1 else 0,
                'avg_duration': statistics.mean(duration_list) if duration_list else 0,
                'std_duration': statistics.stdev(duration_list) if len(duration_list) > 1 else 0,
                'unique_dests': len(data['unique_dests'])
            }
        
        return result
    
    def _calculate_daily_metrics(self, flows: List[NetworkFlow]) -> Dict:
        """
        Calcule les métriques par jour de la semaine
        """
        daily = defaultdict(lambda: {
            'count': 0,
            'bytes': [],
            'duration': []
        })
        
        for flow in flows:
            day = flow.ts.weekday()  # 0 = lundi, 6 = dimanche
            daily[day]['count'] += 1
            daily[day]['bytes'].append((flow.orig_bytes or 0) + (flow.resp_bytes or 0))
            daily[day]['duration'].append(flow.duration or 0)
        
        result = {}
        for day, data in daily.items():
            bytes_list = data['bytes']
            duration_list = [d for d in data['duration'] if d > 0]
            
            result[str(day)] = {
                'avg_count': data['count'] / 4.3,  # Moyenne par jour sur 30 jours
                'avg_bytes': statistics.mean(bytes_list) if bytes_list else 0,
                'std_bytes': statistics.stdev(bytes_list) if len(bytes_list) > 1 else 0,
                'avg_duration': statistics.mean(duration_list) if duration_list else 0,
                'std_duration': statistics.stdev(duration_list) if len(duration_list) > 1 else 0
            }
        
        return result
    
    def _calculate_weekly_metrics(self, flows: List[NetworkFlow]) -> Dict:
        """
        Calcule les métriques hebdomadaires
        """
        weekly = defaultdict(lambda: {
            'count': 0,
            'bytes': [],
            'duration': []
        })
        
        for flow in flows:
            week = flow.ts.isocalendar()[1]  # Numéro de semaine
            weekly[week]['count'] += 1
            weekly[week]['bytes'].append((flow.orig_bytes or 0) + (flow.resp_bytes or 0))
            weekly[week]['duration'].append(flow.duration or 0)
        
        # Moyenne sur les semaines
        counts = [data['count'] for data in weekly.values()]
        all_bytes = [b for data in weekly.values() for b in data['bytes']]
        all_durations = [d for data in weekly.values() for d in data['duration'] if d > 0]
        
        return {
            'avg_weekly_count': statistics.mean(counts) if counts else 0,
            'std_weekly_count': statistics.stdev(counts) if len(counts) > 1 else 0,
            'avg_bytes': statistics.mean(all_bytes) if all_bytes else 0,
            'std_bytes': statistics.stdev(all_bytes) if len(all_bytes) > 1 else 0,
            'avg_duration': statistics.mean(all_durations) if all_durations else 0,
            'std_duration': statistics.stdev(all_durations) if len(all_durations) > 1 else 0
        }
    
    def _calculate_profile_deviation(self, old: Dict, new: Dict) -> float:
        """
        Calcule le score de déviation entre deux profils
        """
        deviations = []
        
        # Comparer les métriques horaires
        old_hourly = old.get('hourly', {})
        new_hourly = new.get('hourly', {})
        
        for hour in range(24):
            str_hour = str(hour)
            if str_hour in old_hourly and str_hour in new_hourly:
                old_data = old_hourly[str_hour]
                new_data = new_hourly[str_hour]
                
                # Déviation sur le nombre de connexions
                if old_data['avg_count'] > 0:
                    count_ratio = abs(new_data['avg_count'] - old_data['avg_count']) / old_data['avg_count']
                    deviations.append(count_ratio * 100)
        
        return statistics.mean(deviations) if deviations else 0
    
    def _clean_old_profiles(self):
        """Nettoie les profils des assets inactifs"""
        with self.app.app_context():
            cutoff = datetime.utcnow() - timedelta(days=30)
            old_assets = NetworkAsset.query.filter(
                NetworkAsset.last_seen < cutoff
            ).all()
            
            for asset in old_assets:
                with self.profile_lock:
                    if asset.ip_address in self.profiles:
                        del self.profiles[asset.ip_address]
    
    def analyze_flow(self, flow: NetworkFlow) -> Optional[Dict]:
        """
        Analyse un flux par rapport au profil de l'asset source
        Retourne un score d'anomalie si détectée
        """
        if not flow.source_ip:
            return None
        
        # Récupérer le profil
        profile = self._get_asset_profile(flow.source_ip)
        if not profile:
            return None
        
        # Analyser selon différentes dimensions
        anomalies = []
        
        # 1. Analyse horaire
        hour_score = self._analyze_hourly(flow, profile)
        if hour_score > 0:
            anomalies.append({
                'type': 'hourly',
                'score': hour_score,
                'description': f"Activité anormale pour l'heure {flow.ts.hour}h"
            })
        
        # 2. Analyse volumétrique
        volume_score = self._analyze_volume(flow, profile)
        if volume_score > 0:
            anomalies.append({
                'type': 'volume',
                'score': volume_score,
                'description': "Volume de données anormal"
            })
        
        # 3. Analyse des destinations
        dest_score = self._analyze_destination(flow, profile)
        if dest_score > 0:
            anomalies.append({
                'type': 'destination',
                'score': dest_score,
                'description': f"Destination inhabituelle: {flow.dest_ip}"
            })
        
        # 4. Analyse de la durée
        duration_score = self._analyze_duration(flow, profile)
        if duration_score > 0:
            anomalies.append({
                'type': 'duration',
                'score': duration_score,
                'description': "Durée de connexion anormale"
            })
        
        if anomalies:
            # Score UEBA final (moyenne des scores d'anomalies)
            ueba_score = int(statistics.mean([a['score'] for a in anomalies]))
            
            self.stats['anomalies_detected'] += 1
            
            return {
                'score': ueba_score,
                'anomalies': anomalies,
                'profile_age': (datetime.utcnow() - flow.ts).days
            }
        
        return None
    
    def _get_asset_profile(self, ip: str) -> Optional[Dict]:
        """
        Récupère le profil d'un asset (cache mémoire ou base)
        """
        # Vérifier le cache mémoire
        if ip in self.profiles:
            return self.profiles[ip]
        
        # Charger depuis la base
        with self.app.app_context():
            asset = NetworkAsset.query.filter_by(ip_address=ip).first()
            if asset and asset.behavioral_profile:
                self.profiles[ip] = asset.behavioral_profile
                return asset.behavioral_profile
        
        return None
    
    def _analyze_hourly(self, flow: NetworkFlow, profile: Dict) -> int:
        """
        Analyse l'activité par rapport au profil horaire
        """
        hourly = profile.get('hourly', {})
        hour = str(flow.ts.hour)
        
        if hour not in hourly:
            return 30  # Pas de données pour cette heure -> anomalie moyenne
        
        hour_data = hourly[hour]
        
        # Vérifier si l'activité est normale pour cette heure
        # Simulation simple - à améliorer avec des stats réelles
        if hour_data['avg_count'] < 1:
            return 40  # Heure habituellement inactive
        
        return 0
    
    def _analyze_volume(self, flow: NetworkFlow, profile: Dict) -> int:
        """
        Analyse le volume de données par rapport au profil
        """
        flow_bytes = (flow.orig_bytes or 0) + (flow.resp_bytes or 0)
        if flow_bytes == 0:
            return 0
        
        # Récupérer les stats volumétriques
        weekly = profile.get('weekly', {})
        avg_bytes = weekly.get('avg_bytes', 0)
        std_bytes = weekly.get('std_bytes', 1)  # Éviter division par zéro
        
        if avg_bytes == 0:
            return 20  # Pas de référence
        
        # Calculer le nombre d'écarts-types
        sigma = (flow_bytes - avg_bytes) / std_bytes
        
        # Déterminer le score
        if sigma > self.THRESHOLD_FACTORS['critical']:
            return 100
        elif sigma > self.THRESHOLD_FACTORS['high']:
            return 75
        elif sigma > self.THRESHOLD_FACTORS['medium']:
            return 50
        elif sigma > self.THRESHOLD_FACTORS['low']:
            return 25
        
        return 0
    
    def _analyze_destination(self, flow: NetworkFlow, profile: Dict) -> int:
        """
        Analyse si la destination est inhabituelle
        """
        hourly = profile.get('hourly', {})
        hour = str(flow.ts.hour)
        
        if hour in hourly:
            hour_data = hourly[hour]
            # Vérifier si la destination est dans les habituelles
            # Simulation - à améliorer
            return 0
        
        return 30  # Destination inhabituelle
    
    def _analyze_duration(self, flow: NetworkFlow, profile: Dict) -> int:
        """
        Analyse la durée de connexion par rapport au profil
        """
        if not flow.duration or flow.duration == 0:
            return 0
        
        weekly = profile.get('weekly', {})
        avg_duration = weekly.get('avg_duration', 0)
        std_duration = weekly.get('std_duration', 1)
        
        if avg_duration == 0:
            return 20
        
        sigma = (flow.duration - avg_duration) / std_duration
        
        if sigma > self.THRESHOLD_FACTORS['high']:
            return 60
        elif sigma > self.THRESHOLD_FACTORS['medium']:
            return 30
        elif sigma < -self.THRESHOLD_FACTORS['medium']:  # Connexion trop courte
            return 20
        
        return 0
    
    def get_asset_anomaly_score(self, ip: str) -> int:
        """
        Retourne le score d'anomalie global pour un asset
        """
        with self.app.app_context():
            asset = NetworkAsset.query.filter_by(ip_address=ip).first()
            if asset:
                return asset.deviation_score or 0
        return 0
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques du moteur"""
        with self.profile_lock:
            profiled_count = len(self.profiles)
        
        return {
            **self.stats,
            'profiles_in_memory': profiled_count,
            'thresholds': self.THRESHOLD_FACTORS
        }


# Instance singleton
baselining_engine = None

def init_baselining_engine(app):
    """Initialise le moteur UEBA"""
    global baselining_engine
    baselining_engine = BaseliningEngine(app)
    baselining_engine.start()
    return baselining_engine

def get_baselining_engine():
    """Récupère l'instance du moteur UEBA"""
    return baselining_engine