"""
Client Threat Intelligence pour ACRA SOC
Interrogation des bases de réputation (AbuseIPDB, AlienVault OTX, etc.)
"""
import requests
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from functools import lru_cache
from src.core.event_bus import bus
from src.models import ThreatIntelligence
from src.extensions import db

# Configuration
ABUSEIPDB_API_KEY = "VOTRE_CLE_API"  # À mettre dans .env
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ALIENVAULT_API_KEY = "VOTRE_CLE_API"  # À mettre dans .env
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/"

class ThreatIntelligenceClient:
    """
    Client pour interroger les bases de Threat Intelligence externes
    Gère le cache local et le rate limiting
    """
    
    def __init__(self, app=None):
        self.app = app
        self.cache = {}  # Cache mémoire {ip: (timestamp, score)}
        self.cache_ttl = 3600  # 1 heure
        self.last_request = 0
        self.min_request_interval = 1  # 1 seconde entre requêtes
        
        # Configuration depuis l'app
        if app:
            self.abuseipdb_key = app.config.get('ABUSEIPDB_API_KEY', '')
            self.alienvault_key = app.config.get('ALIENVAULT_API_KEY', '')
        else:
            self.abuseipdb_key = ''
            self.alienvault_key = ''
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def _rate_limit(self):
        """Respecte le rate limiting des APIs"""
        now = time.time()
        if now - self.last_request < self.min_request_interval:
            time.sleep(self.min_request_interval - (now - self.last_request))
        self.last_request = time.time()
    
    def _get_from_cache(self, ip: str) -> Optional[int]:
        """Récupère le score depuis le cache mémoire"""
        if ip in self.cache:
            timestamp, score = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return score
            else:
                del self.cache[ip]
        return None
    
    def _save_to_cache(self, ip: str, score: int):
        """Sauvegarde le score dans le cache mémoire"""
        self.cache[ip] = (time.time(), score)
    
    def _get_from_db(self, ip: str) -> Optional[ThreatIntelligence]:
        """Récupère une entrée TI depuis la base locale"""
        with self.app.app_context():
            return ThreatIntelligence.query.filter_by(
                indicator=ip, 
                type='ip'
            ).first()
    
    def _save_to_db(self, ip: str, score: int, source: str, data: dict):
        """Sauvegarde une entrée TI dans la base locale"""
        with self.app.app_context():
            ti = ThreatIntelligence(
                indicator=ip,
                type='ip',
                severity=score,
                confidence=data.get('confidence', 50),
                source=source,
                description=data.get('description', ''),
                tags=data.get('tags', []),
                raw_data=data
            )
            db.session.add(ti)
            db.session.commit()
    
    def check_abuseipdb(self, ip: str) -> Tuple[int, dict]:
        """
        Interroge AbuseIPDB pour obtenir le score de réputation d'une IP
        Retourne: (score 0-100, données brutes)
        """
        if not self.abuseipdb_key:
            self.logger.warning("Clé API AbuseIPDB non configurée")
            return 0, {}
        
        self._rate_limit()
        
        headers = {
            'Accept': 'application/json',
            'Key': self.abuseipdb_key
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        
        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Calcul du score (0-100)
                abuse_confidence = data.get('abuseConfidenceScore', 0)
                total_reports = data.get('totalReports', 0)
                
                # Score basé sur le niveau de confiance + bonus pour nombreux reports
                score = abuse_confidence
                if total_reports > 10:
                    score = min(score + 10, 100)
                
                self.logger.info(f"AbuseIPDB: {ip} -> score {score}")
                return score, data
            else:
                self.logger.error(f"Erreur AbuseIPDB: {response.status_code}")
                return 0, {}
                
        except Exception as e:
            self.logger.error(f"Exception AbuseIPDB: {e}")
            return 0, {}
    
    def check_alienvault(self, ip: str) -> Tuple[int, dict]:
        """
        Interroge AlienVault OTX pour obtenir des informations sur une IP
        Retourne: (score 0-100, données brutes)
        """
        if not self.alienvault_key:
            self.logger.warning("Clé API AlienVault non configurée")
            return 0, {}
        
        self._rate_limit()
        
        headers = {'X-OTX-API-KEY': self.alienvault_key}
        
        try:
            # Récupération des pulses pour cette IP
            url = f"{ALIENVAULT_URL}ip/{ip}/reputation"
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                # Calcul du score basé sur le nombre de pulses
                pulses = data.get('pulse_count', 0)
                score = min(pulses * 10, 100)
                
                self.logger.info(f"AlienVault: {ip} -> score {score}")
                return score, data
            else:
                return 0, {}
                
        except Exception as e:
            self.logger.error(f"Exception AlienVault: {e}")
            return 0, {}
    
    def get_threat_score(self, ip: str, use_cache: bool = True) -> int:
        """
        Récupère le score de menace pour une IP (0-100)
        Combine plusieurs sources et utilise le cache
        """
        # 1. Vérifier le cache mémoire
        if use_cache:
            cached = self._get_from_cache(ip)
            if cached is not None:
                return cached
        
        # 2. Vérifier la base locale
        db_entry = self._get_from_db(ip)
        if db_entry:
            score = db_entry.severity
            self._save_to_cache(ip, score)
            
            # Publier l'événement
            bus.publish('threat_intel', {
                'ip': ip,
                'score': score,
                'source': 'database',
                'confidence': db_entry.confidence
            })
            
            return score
        
        # 3. Interroger AbuseIPDB
        score1, data1 = self.check_abuseipdb(ip)
        
        # 4. Interroger AlienVault
        score2, data2 = self.check_alienvault(ip)
        
        # 5. Combiner les scores (maximum)
        final_score = max(score1, score2)
        
        # 6. Sauvegarder dans la base et le cache
        if final_score > 0:
            # Déterminer la source principale
            source = 'abuseipdb' if score1 >= score2 else 'alienvault'
            combined_data = {
                'abuseipdb': data1,
                'alienvault': data2,
                'combined_score': final_score
            }
            
            self._save_to_db(ip, final_score, source, combined_data)
            self._save_to_cache(ip, final_score)
            
            # Publier l'événement
            bus.publish('threat_intel', {
                'ip': ip,
                'score': final_score,
                'source': source,
                'confidence': final_score
            })
        
        return final_score
    
    def batch_check(self, ips: List[str]) -> Dict[str, int]:
        """
        Vérifie plusieurs IPs en une seule fois
        Utile pour le scoring en temps réel
        """
        results = {}
        for ip in ips:
            results[ip] = self.get_threat_score(ip)
        return results


# Instance singleton pour utilisation dans toute l'app
ti_client = None

def init_ti_client(app):
    """Initialise le client Threat Intelligence"""
    global ti_client
    ti_client = ThreatIntelligenceClient(app)
    return ti_client

def get_ti_client():
    """Récupère l'instance du client TI"""
    return ti_client