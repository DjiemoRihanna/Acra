import redis
import logging
from src.core.constants import REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_BLACKLIST_KEY

logger = logging.getLogger(__name__)

class TIClient:
    def __init__(self):
        try:
            self.redis_client = redis.Redis(
                host=REDIS_HOST, 
                port=REDIS_PORT, 
                db=REDIS_DB, 
                decode_responses=True
            )
        except Exception as e:
            logger.error(f"Erreur de connexion Redis : {e}")

    def get_score(self, ip):
        # Vérification Blacklist Redis (Constante utilisée ici)
        if self.redis_client.sismember(REDIS_BLACKLIST_KEY, ip):
            logger.info(f"IP {ip} trouvée dans la blacklist locale Redis.")
            return 100
        
        # Logique d'appel API AbuseIPDB (à compléter avec ton code existant)
        return 0