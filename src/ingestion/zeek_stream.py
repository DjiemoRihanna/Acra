"""
Streamer Zeek amélioré pour ACRA SOC
Ingestion en temps réel des logs réseau avec fingerprinting automatique
"""
import eventlet
eventlet.monkey_patch()

import json
import os
import time
import psycopg2
import threading
import sys
import signal
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from functools import lru_cache
from psycopg2.extras import execute_values

# --- CONFIGURATION CENTRALISÉE ---
class ZeekConfig:
    """Configuration centralisée du streamer Zeek"""
    
    # Chemins des logs
    LOG_DIR = "/app/data/zeek_logs/"
    LOG_FILES = {
        'conn': "conn.log",
        'ssl': "ssl.log", 
        'dns': "dns.log",
        'http': "http.log",
        'files': "files.log"
    }
    
    # Réseaux privés
    PRIVATE_NETWORKS = (
        '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.2', '172.30.', '172.31.', '127.'
    )
    
    # Classification des ports
    PORTS = {
        'ROUTER': {53, 67, 68, 161, 162, 123},  # DNS, DHCP, SNMP, NTP
        'SERVER': {22, 21, 25, 80, 443, 3306, 5432, 27017, 6379, 9200, 11211},
        'PRINTER': {9100, 515, 631, 443},
        'IOT': {5353, 1900, 5683, 8883, 1883},  # mDNS, UPnP, CoAP, MQTT
        'CAMERA': {554, 37777, 8000, 8080},  # RTSP, Dahua, streaming
        'VOIP': {5060, 5061, 10000, 20000},  # SIP, RTP
        'ICS': {502, 44818, 1911, 1962},  # Modbus, EtherNet/IP
    }
    
    # Services connus
    SERVICES = {
        'ROUTER': {'dns', 'dhcp', 'ntp', 'snmp'},
        'SERVER': {'ssh', 'http', 'https', 'mysql', 'postgresql', 'redis', 'elasticsearch'},
        'DATABASE': {'mysql', 'postgresql', 'redis', 'mongodb', 'cassandra'},
        'IOT': {'mdns', 'upnp', 'coap', 'mqtt'},
    }
    
    # Config DB
    DB_CONNECT_TIMEOUT = 10
    DB_RETRY_ATTEMPTS = 10
    DB_RETRY_DELAY = 2

# --- LOGGER STRUCTURÉ ---
class StructuredLogger:
    """Logger structuré pour un meilleur monitoring"""
    
    @staticmethod
    def info(message: str, **kwargs):
        """Log niveau info"""
        timestamp = datetime.now().isoformat()
        log_data = {"timestamp": timestamp, "level": "INFO", "message": message, **kwargs}
        print(json.dumps(log_data), flush=True)
    
    @staticmethod
    def error(message: str, **kwargs):
        """Log niveau error"""
        timestamp = datetime.now().isoformat()
        log_data = {"timestamp": timestamp, "level": "ERROR", "message": message, **kwargs}
        print(json.dumps(log_data), flush=True)
    
    @staticmethod
    def warning(message: str, **kwargs):
        """Log niveau warning"""
        timestamp = datetime.now().isoformat()
        log_data = {"timestamp": timestamp, "level": "WARNING", "message": message, **kwargs}
        print(json.dumps(log_data), flush=True)
    
    @staticmethod
    def debug(message: str, **kwargs):
        """Log niveau debug"""
        timestamp = datetime.now().isoformat()
        log_data = {"timestamp": timestamp, "level": "DEBUG", "message": message, **kwargs}
        print(json.dumps(log_data), flush=True)

logger = StructuredLogger()

# --- CACHE POUR PERFORMANCE ---
class DeviceCache:
    """Cache pour éviter les requêtes DB répétitives et classification coûteuse"""
    
    def __init__(self, ttl_minutes: int = 30, max_size: int = 10000):
        self.cache: Dict[str, Tuple[datetime, str]] = {}
        self.ttl = timedelta(minutes=ttl_minutes)
        self.max_size = max_size
    
    def get(self, ip: str, port: int, service: str) -> Optional[str]:
        """Récupère le type d'appareil depuis le cache"""
        cache_key = f"{ip}:{port}:{service}"
        
        if cache_key in self.cache:
            cached_time, device_type = self.cache[cache_key]
            if datetime.now() - cached_time < self.ttl:
                return device_type
        
        return None
    
    def set(self, ip: str, port: int, service: str, device_type: str):
        """Stocke le type d'appareil dans le cache"""
        cache_key = f"{ip}:{port}:{service}"
        
        # Éviction LRU si le cache est plein
        if len(self.cache) >= self.max_size:
            # Supprime le premier élément (le plus ancien)
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        
        self.cache[cache_key] = (datetime.now(), device_type)
    
    def clear(self):
        """Vide le cache"""
        self.cache.clear()

# --- GESTION DE LA BASE DE DONNÉES ---
class DatabaseManager:
    """Gestion robuste des connexions à la base de données"""
    
    @staticmethod
    def get_connection() -> psycopg2.extensions.connection:
        """Établit une connexion avec retry et backoff exponentiel"""
        db_url = os.getenv('DATABASE_URL', "dbname=acra user=acra_admin password=changeme123 host=postgres")
        
        for attempt in range(ZeekConfig.DB_RETRY_ATTEMPTS):
            try:
                conn = psycopg2.connect(
                    db_url,
                    connect_timeout=ZeekConfig.DB_CONNECT_TIMEOUT,
                    keepalives=1,
                    keepalives_idle=30,
                    keepalives_interval=10,
                    keepalives_count=5
                )
                logger.info("Connexion DB établie", attempt=attempt+1)
                return conn
            except psycopg2.OperationalError as e:
                wait_time = ZeekConfig.DB_RETRY_DELAY * (2 ** attempt)  # Backoff exponentiel
                logger.warning("Connexion DB échouée", 
                             attempt=attempt+1, 
                             error=str(e), 
                             wait_seconds=wait_time)
                time.sleep(wait_time)
        
        raise Exception(f"Impossible de se connecter à la DB après {ZeekConfig.DB_RETRY_ATTEMPTS} tentatives")
    
    @staticmethod
    def wait_for_tables(conn: psycopg2.extensions.connection):
        """Attend que les tables nécessaires soient créées"""
        tables_to_check = ['network_flows', 'network_assets']
        
        while True:
            try:
                with conn.cursor() as cur:
                    missing_tables = []
                    for table in tables_to_check:
                        cur.execute("""
                            SELECT EXISTS (
                                SELECT FROM information_schema.tables 
                                WHERE table_name = %s
                            );
                        """, (table,))
                        if not cur.fetchone()[0]:
                            missing_tables.append(table)
                    
                    if not missing_tables:
                        logger.info("Toutes les tables sont prêtes")
                        return
                    else:
                        logger.debug("Tables manquantes", missing=missing_tables)
                        time.sleep(3)
            except Exception as e:
                logger.error("Erreur vérification tables", error=str(e))
                time.sleep(2)

# --- FINGERPRINTING AMÉLIORÉ ---
class DeviceClassifier:
    """Système avancé de fingerprinting des équipements réseau"""
    
    def __init__(self):
        self.cache = DeviceCache()
        
        # Patterns pour les services cloud
        self.cloud_patterns = {
            'aws': ['amazonaws.com', '.aws.', 's3.amazonaws.com'],
            'azure': ['.azure.', '.microsoft.com', 'blob.core.windows.net'],
            'google': ['.google.', '.gstatic.com', '.googleapis.com'],
            'cloudflare': ['.cloudflare.com'],
            'akamai': ['.akamai.', '.akamaiedge.net']
        }
        
        # Heuristiques pour les appareils spécifiques
        self.device_heuristics = {
            'printer': {
                'ports': {9100, 515, 631, 443},
                'services': {'ipp', 'http', 'https'},
                'behavior': ['frequent_small_packets', 'periodic_scans']
            },
            'camera': {
                'ports': {554, 37777, 8000, 8080, 8008},
                'services': {'rtsp', 'http'},
                'behavior': ['constant_stream', 'high_upload']
            },
            'nas': {
                'ports': {445, 139, 2049, 111},
                'services': {'smb', 'nfs', 'rpc'},
                'behavior': ['large_transfers', 'multiple_connections']
            }
        }
    
    def is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est dans un réseau privé"""
        return any(ip.startswith(network) for network in ZeekConfig.PRIVATE_NETWORKS)
    
    def is_cloud_service(self, domain: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Détecte les services cloud"""
        if not domain:
            return False, None
        
        domain_lower = domain.lower()
        for cloud, patterns in self.cloud_patterns.items():
            if any(pattern in domain_lower for pattern in patterns):
                return True, cloud
        
        return False, None
    
    def classify_by_port_service(self, port: int, service: str) -> Optional[str]:
        """Classification basée sur le port et le service"""
        service_lower = service.lower() if service else ''
        
        # Vérification par port
        for device_type, ports in ZeekConfig.PORTS.items():
            if port in ports:
                return device_type.lower()
        
        # Vérification par service
        for device_type, services in ZeekConfig.SERVICES.items():
            if service_lower in services:
                return device_type.lower()
        
        return None
    
    def analyze_behavior(self, src_ip: str, dst_ip: str, bytes_sent: int, bytes_received: int) -> List[str]:
        """Analyse le comportement réseau pour classification"""
        behaviors = []
        
        # Comportement serveur (plus de données envoyées que reçues)
        if bytes_sent > bytes_received * 2:
            behaviors.append('server_behavior')
        
        # Comportement client (plus de données reçues)
        if bytes_received > bytes_sent * 2:
            behaviors.append('client_behavior')
        
        # Scan de ports (beaucoup de connexions courtes)
        # À implémenter avec historique
        
        return behaviors
    
    def classify_device(self, ip: str, port: int, service: str, 
                       is_internal: bool, is_receiver: bool,
                       domain: Optional[str] = None,
                       bytes_sent: int = 0, bytes_received: int = 0) -> str:
        """Classification complète d'un appareil"""
        
        # 1. Vérifier le cache
        cached = self.cache.get(ip, port, service)
        if cached:
            return cached
        
        # 2. Détection cloud
        is_cloud, cloud_provider = self.is_cloud_service(domain)
        if is_cloud:
            device_type = 'cloud'
            if cloud_provider:
                device_type = f"cloud_{cloud_provider}"
            self.cache.set(ip, port, service, device_type)
            return device_type
        
        # 3. Classification par port/service
        port_based = self.classify_by_port_service(port, service)
        if port_based:
            self.cache.set(ip, port, service, port_based)
            return port_based
        
        # 4. Si IP externe et non cloud
        if not is_internal and not is_cloud:
            device_type = 'external'
            self.cache.set(ip, port, service, device_type)
            return device_type
        
        # 5. Analyse comportementale (pour IP internes)
        if is_internal:
            behaviors = self.analyze_behavior(ip, "0.0.0.0", bytes_sent, bytes_received)
            
            # Serveur interne
            if is_receiver and 'server_behavior' in behaviors:
                device_type = 'server'
            # Routeur/gateway
            elif is_receiver and port in {53, 67, 68}:
                device_type = 'router'
            # Par défaut
            else:
                device_type = 'computer'
        else:
            device_type = 'external'
        
        # 6. Application des heuristiques spécifiques
        for dev_type, heuristics in self.device_heuristics.items():
            if port in heuristics['ports'] or (service and service.lower() in heuristics['services']):
                device_type = dev_type
                break
        
        # 7. Mise en cache
        self.cache.set(ip, port, service, device_type)
        
        return device_type

# --- PROCESSUS D'INGESTION ---
class ZeekStreamer:
    """Streamer principal pour les logs Zeek"""
    
    def __init__(self):
        self.running = True
        self.threads = []
        self.classifier = DeviceClassifier()
        self.setup_signal_handlers()
        
        logger.info("Initialisation du streamer Zeek")
    
    def setup_signal_handlers(self):
        """Configure les handlers pour un arrêt propre"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Gère les signaux d'arrêt"""
        logger.info("Signal d'arrêt reçu", signal=signum)
        self.running = False
        
        # Arrêt propre des threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("Streamer arrêté proprement")
        sys.exit(0)
    
    def _validate_log_data(self, data: Dict[str, Any], log_type: str) -> bool:
        """Valide les données du log"""
        required_fields = {
            'conn': ['ts', 'uid', 'id.orig_h', 'id.resp_h'],
            'ssl': ['ts', 'server_name'],
            'dns': ['ts', 'query']
        }
        
        if log_type not in required_fields:
            return True
        
        for field in required_fields[log_type]:
            if field not in data:
                logger.warning("Champ manquant dans le log", 
                             log_type=log_type, 
                             field=field,
                             data_keys=list(data.keys()))
                return False
        
        return True
    
    def _clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Nettoie et normalise les données"""
        cleaned = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                cleaned[key] = value.strip()
            else:
                cleaned[key] = value
        
        # Normalisation des IP
        for ip_field in ['id.orig_h', 'id.resp_h']:
            if ip_field in cleaned and cleaned[ip_field]:
                cleaned[ip_field] = cleaned[ip_field].strip()
        
        return cleaned
    
    def _process_network_flow(self, cur, data: Dict[str, Any]):
        """Traite un flux réseau (conn.log)"""
        try:
            cur.execute("""
                INSERT INTO network_flows 
                (ts, uid, source_ip, source_port, dest_ip, dest_port, 
                 protocol, service, orig_bytes, resp_bytes, duration)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (uid) DO NOTHING
            """, (
                datetime.fromtimestamp(data['ts']),
                data['uid'],
                data.get('id.orig_h'),
                data.get('id.orig_p', 0),
                data.get('id.resp_h'),
                data.get('id.resp_p', 0),
                data.get('proto', 'unknown'),
                data.get('service', 'unknown'),
                data.get('orig_bytes', 0) or 0,
                data.get('resp_bytes', 0) or 0,
                data.get('duration', 0) or 0
            ))
        except Exception as e:
            logger.error("Erreur insertion network_flows", error=str(e), uid=data.get('uid'))
            raise
    
    def _update_network_assets(self, cur, data: Dict[str, Any], log_type: str):
        """Met à jour les assets réseau avec fingerprinting"""
        src_ip = data.get('id.orig_h')
        dst_ip = data.get('id.resp_h')
        
        if not src_ip:
            return
        
        # Données pour la classification
        resp_port = data.get('id.resp_p', 0)
        service = data.get('service', 'unknown')
        bytes_sent = data.get('orig_bytes', 0) or 0
        bytes_received = data.get('resp_bytes', 0) or 0
        
        # Domain pour SSL/DNS
        domain = None
        if log_type == 'ssl':
            domain = data.get('server_name')
        elif log_type == 'dns':
            domain = data.get('query')
        
        # Traitement des deux IPs (source et destination)
        if log_type == 'conn' and dst_ip:
            ips_to_process = [(src_ip, False), (dst_ip, True)]
        else:
            ips_to_process = [(src_ip, False)]
        
        for ip, is_receiver in ips_to_process:
            if not ip:
                continue
            
            is_internal = self.classifier.is_private_ip(ip)
            
            # Classification
            device_type = self.classifier.classify_device(
                ip=ip,
                port=resp_port,
                service=service,
                is_internal=is_internal,
                is_receiver=is_receiver,
                domain=domain,
                bytes_sent=bytes_sent if not is_receiver else 0,
                bytes_received=bytes_received if not is_receiver else 0
            )
            
            # Détermination du type d'asset
            asset_type = 'internal' if is_internal else 'external'
            
            # Données à envoyer/recevoir
            sent = bytes_sent if not is_receiver else 0
            received = bytes_received if not is_receiver else 0
            
            try:
                # Mise à jour de l'asset
                cur.execute("""
                    INSERT INTO network_assets 
                    (ip_address, asset_type, device_type, 
                     total_bytes_sent, total_bytes_received, 
                     last_seen, status, os_info)
                    VALUES (%s, %s, %s, %s, %s, %s, 'online', %s)
                    ON CONFLICT (ip_address) DO UPDATE SET
                        total_bytes_sent = network_assets.total_bytes_sent + EXCLUDED.total_bytes_sent,
                        total_bytes_received = network_assets.total_bytes_received + EXCLUDED.total_bytes_received,
                        last_seen = EXCLUDED.last_seen,
                        status = 'online',
                        device_type = CASE 
                            WHEN network_assets.device_type IN ('server', 'router', 'printer', 'cloud', 'firewall') 
                            THEN network_assets.device_type 
                            ELSE EXCLUDED.device_type 
                        END,
                        os_info = COALESCE(network_assets.os_info, EXCLUDED.os_info);
                """, (ip, asset_type, device_type, sent, received, datetime.now(), 'unknown'))
                
                # Mise à jour des domaines pour SSL/DNS
                if domain:
                    cur.execute("""
                        UPDATE network_assets 
                        SET top_domains = (
                            SELECT jsonb_agg(DISTINCT x)
                            FROM jsonb_array_elements_text(
                                COALESCE(top_domains::jsonb, '[]'::jsonb) || jsonb_build_array(%s)
                            ) AS x
                            WHERE x IS NOT NULL
                        )
                        WHERE ip_address = %s;
                    """, (domain, ip))
                    
            except Exception as e:
                logger.error("Erreur mise à jour network_assets", 
                           ip=ip, error=str(e))
                raise
    
    def _process_log_line(self, conn, line: str, log_type: str):
        """Traite une ligne de log individuelle"""
        try:
            # Parse JSON
            data = json.loads(line.strip())
            
            # Validation
            if not self._validate_log_data(data, log_type):
                return
            
            # Nettoyage
            data = self._clean_data(data)
            
            with conn.cursor() as cur:
                # Traitement spécifique au type de log
                if log_type == 'conn':
                    self._process_network_flow(cur, data)
                
                # Mise à jour des assets
                self._update_network_assets(cur, data, log_type)
                
                # Commit
                conn.commit()
                
                # Log debug
                logger.debug("Ligne traitée", 
                           log_type=log_type, 
                           uid=data.get('uid'),
                           src_ip=data.get('id.orig_h'),
                           dst_ip=data.get('id.resp_h'))
                
        except json.JSONDecodeError as e:
            logger.warning("JSON invalide", log_type=log_type, error=str(e), line_preview=line[:100])
        except Exception as e:
            logger.error("Erreur traitement ligne", 
                       log_type=log_type, 
                       error=str(e),
                       line_preview=line[:100] if line else 'empty')
            if conn:
                conn.rollback()
    
    def _stream_log_file(self, log_type: str):
        """Stream un fichier de log spécifique"""
        log_file = os.path.join(ZeekConfig.LOG_DIR, ZeekConfig.LOG_FILES.get(log_type, ''))
        
        if not os.path.exists(log_file):
            logger.warning("Fichier log non trouvé", log_type=log_type, path=log_file)
            time.sleep(5)
            return
        
        logger.info("Démarrage streaming", log_type=log_type, file=log_file)
        
        while self.running:
            try:
                # Connexion DB
                conn = DatabaseManager.get_connection()
                DatabaseManager.wait_for_tables(conn)
                
                # Ouverture du fichier
                with open(log_file, 'r') as f:
                    # Position à la fin si le fichier existe déjà
                    if os.path.getsize(log_file) > 1024:
                        f.seek(0, os.SEEK_END)
                    
                    # Lecture en continu
                    while self.running:
                        line = f.readline()
                        if not line:
                            # Vérifier si le fichier a été rotationné
                            if not os.path.exists(log_file):
                                logger.warning("Fichier log disparu", log_type=log_type)
                                break
                            time.sleep(0.1)
                            continue
                        
                        # Traitement de la ligne
                        self._process_log_line(conn, line, log_type)
                
                conn.close()
                
            except Exception as e:
                logger.error("Erreur streaming", log_type=log_type, error=str(e))
                time.sleep(5)
    
    def start_streaming(self, log_types: List[str] = None):
        """Démarre le streaming pour les types de logs spécifiés"""
        if log_types is None:
            log_types = ['conn', 'ssl', 'dns']
        
        logger.info("Démarrage du pipeline ACRA", log_types=log_types)
        
        # Démarrer un thread par type de log
        for log_type in log_types:
            thread = threading.Thread(
                target=self._stream_log_file,
                args=(log_type,),
                name=f"zeek-{log_type}",
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            logger.info("Thread démarré", thread=thread.name)
        
        # Garder le thread principal actif
        try:
            while self.running:
                # Monitoring des threads
                alive_threads = [t for t in self.threads if t.is_alive()]
                if len(alive_threads) < len(self.threads):
                    logger.warning("Threads morts", 
                                 total=len(self.threads), 
                                 alive=len(alive_threads))
                
                time.sleep(10)
                
        except KeyboardInterrupt:
            logger.info("Interruption clavier")
            self.running = False
        
        # Attendre la fin des threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("Streaming terminé")

# --- POINT D'ENTRÉE ---
def main():
    """Fonction principale"""
    streamer = ZeekStreamer()
    
    try:
        streamer.start_streaming()
    except Exception as e:
        logger.error("Erreur fatale", error=str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()