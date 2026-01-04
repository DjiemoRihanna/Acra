import redis
import json
import os

class EventBus:
    def __init__(self):
        # Configuration Redis (utilise le nom du service défini dans docker-compose)
        self.redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/0')
        try:
            self.client = redis.from_url(self.redis_url, decode_responses=True)
            print(f"📡 [EVENT BUS] Connecté à Redis sur {self.redis_url}")
        except Exception as e:
            print(f"❌ [EVENT BUS] Erreur connexion Redis : {e}")
            self.client = None

    def publish_flow(self, flow_data):
        """
        Diffuse un flux réseau capturé en temps réel.
        Le Membre C s'abonnera au canal 'network_events' via WebSocket.
        """
        if self.client:
            try:
                self.client.publish('network_events', json.dumps(flow_data))
            except Exception as e:
                print(f"⚠️ [EVENT BUS] Échec publication flux : {e}")

    def publish_alert(self, alert_data):
        """
        Diffuse une alerte de sécurité.
        Prévu pour les itérations futures (détection).
        """
        if self.client:
            try:
                self.client.publish('security_alerts', json.dumps(alert_data))
            except Exception as e:
                print(f"⚠️ [EVENT BUS] Échec publication alerte : {e}")

# Instance unique (Singleton) pour tout le projet
bus = EventBus()