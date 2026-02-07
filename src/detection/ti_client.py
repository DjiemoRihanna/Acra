import redis
import requests
import os
from dotenv import load_dotenv

load_dotenv()

class TIClient:
    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

    def get_ip_reputation(self, ip):
        # 1. Vérifier si l'IP est dans la Blacklist Redis (Update Manager)
        if self.r.sismember("blacklist_ips", ip):
            return 100
        
        # 2. Vérifier Cache Redis pour éviter appels API inutiles
        cached_score = self.r.get(f"score:{ip}")
        if cached_score:
            return int(cached_score)

        # 3. Appel API AbuseIPDB
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            headers = {'Accept': 'application/json', 'Key': self.api_key}
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                score = response.json()['data']['abuseConfidenceScore']
                self.r.setex(f"score:{ip}", 3600, score) # Cache 1 heure
                return score
        except:
            return 0
        return 0