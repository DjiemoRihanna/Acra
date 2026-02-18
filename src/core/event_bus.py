"""
ACRA - Bus d'événements Redis
Gère la communication temps réel entre les services
"""
import redis
import json
import os
import threading
from typing import Dict, Any, Callable, Optional

class EventBus:
    """
    Bus d'événements centralisé utilisant Redis Pub/Sub
    Gère la communication entre Zeek, Scapy et le frontend WebSocket
    """
    
    # Canaux disponibles
    CHANNELS = {
        'ZEEK_FLOW': 'zeek:flows',           # Flux réseau de Zeek
        'ZEEK_ALERT': 'zeek:alerts',          # Alertes Zeek
        'SCAPY_DEVICE': 'scapy:devices',      # Mise à jour appareils Scapy
        'SCAPY_TOPOLOGY': 'scapy:topology',   # Topologie complète
        'SCAPY_PACKET': 'scapy:packets',      # Paquets individuels
        'SYSTEM_STATUS': 'system:status',     # Statut des services
        'SECURITY_ALERT': 'security:alerts'   # Alertes de sécurité
    }
    
    def __init__(self):
        """Initialise la connexion Redis"""
        self.redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/0')
        self.subscribers = {}
        self.listeners = []
        
        try:
            # Client pour publication
            self.client = redis.from_url(self.redis_url, decode_responses=True)
            
            # Client séparé pour souscription (nécessaire pour pub/sub)
            self.pubsub_client = redis.from_url(self.redis_url, decode_responses=True)
            self.pubsub = self.pubsub_client.pubsub()
            
            print(f"📡 [EVENT BUS] Connecté à Redis sur {self.redis_url}")
        except Exception as e:
            print(f"❌ [EVENT BUS] Erreur connexion Redis : {e}")
            self.client = None
            self.pubsub = None
    
    # --- MÉTHODES DE PUBLICATION ---
    
    def publish(self, channel: str, data: Dict[str, Any]):
        """
        Publie des données sur un canal Redis
        
        Args:
            channel: Nom du canal (utiliser CHANNELS)
            data: Données à publier (seront converties en JSON)
        """
        if self.client:
            try:
                # Ajouter timestamp si non présent
                if 'timestamp' not in data:
                    from datetime import datetime
                    data['timestamp'] = datetime.now().isoformat()
                
                self.client.publish(channel, json.dumps(data))
                print(f"📤 [EVENT BUS] Publié sur {channel}: {data.get('type', 'data')}")
            except Exception as e:
                print(f"⚠️ [EVENT BUS] Échec publication sur {channel}: {e}")
    
    def publish_zeek_flow(self, flow_data: Dict[str, Any]):
        """Publie un flux réseau de Zeek"""
        flow_data['source'] = 'zeek'
        self.publish(self.CHANNELS['ZEEK_FLOW'], flow_data)
    
    def publish_zeek_alert(self, alert_data: Dict[str, Any]):
        """Publie une alerte de Zeek"""
        alert_data['source'] = 'zeek'
        self.publish(self.CHANNELS['ZEEK_ALERT'], alert_data)
    
    def publish_scapy_device(self, device_data: Dict[str, Any]):
        """Publie une mise à jour d'appareil détecté par Scapy"""
        device_data['source'] = 'scapy'
        device_data['type'] = 'device_update'
        self.publish(self.CHANNELS['SCAPY_DEVICE'], device_data)
    
    def publish_scapy_topology(self, topology_data: Dict[str, Any]):
        """Publie la topologie réseau complète de Scapy"""
        topology_data['source'] = 'scapy'
        topology_data['type'] = 'topology'
        self.publish(self.CHANNELS['SCAPY_TOPOLOGY'], topology_data)
    
    def publish_scapy_packet(self, packet_data: Dict[str, Any]):
        """Publie un paquet individuel capturé par Scapy"""
        packet_data['source'] = 'scapy'
        packet_data['type'] = 'packet'
        self.publish(self.CHANNELS['SCAPY_PACKET'], packet_data)
    
    def publish_system_status(self, status_data: Dict[str, Any]):
        """Publie le statut d'un service"""
        self.publish(self.CHANNELS['SYSTEM_STATUS'], status_data)
    
    # --- MÉTHODES DE SOUSCRIPTION ---
    
    def subscribe(self, channel: str, callback: Callable[[Dict[str, Any]], None]):
        """
        Souscrit à un canal et exécute un callback à chaque message
        
        Args:
            channel: Canal à écouter
            callback: Fonction à appeler avec les données reçues
        """
        if not self.pubsub:
            print(f"❌ [EVENT BUS] Impossible de souscrire: Redis non disponible")
            return
        
        if channel not in self.subscribers:
            self.subscribers[channel] = []
            self.pubsub.subscribe(**{channel: self._message_handler})
        
        self.subscribers[channel].append(callback)
        print(f"👂 [EVENT BUS] Nouveau subscriber sur {channel}")
    
    def _message_handler(self, message):
        """Handler interne pour les messages Redis"""
        if message['type'] == 'message':
            channel = message['channel']
            try:
                data = json.loads(message['data'])
                
                # Appeler tous les callbacks pour ce canal
                if channel in self.subscribers:
                    for callback in self.subscribers[channel]:
                        try:
                            callback(data)
                        except Exception as e:
                            print(f"⚠️ [EVENT BUS] Erreur callback sur {channel}: {e}")
            except json.JSONDecodeError:
                print(f"⚠️ [EVENT BUS] Message JSON invalide sur {channel}")
    
    def start_listening(self):
        """Démarre l'écoute Redis dans un thread séparé"""
        if not self.pubsub:
            return
        
        def listener():
            print(f"🎧 [EVENT BUS] Démarrage de l'écoute Redis...")
            for message in self.pubsub.listen():
                # Le handler est déjà appelé automatiquement via subscribe
                pass
        
        thread = threading.Thread(target=listener, daemon=True)
        thread.start()
        self.listeners.append(thread)
    
    def stop_listening(self):
        """Arrête l'écoute Redis"""
        if self.pubsub:
            self.pubsub.unsubscribe()
        print(f"🛑 [EVENT BUS] Arrêt de l'écoute")

# Instance unique (Singleton) pour tout le projet
bus = EventBus()

# Démarrer l'écoute automatiquement
bus.start_listening()