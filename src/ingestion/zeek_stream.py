import eventlet
eventlet.monkey_patch()

import json
import os
import time
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime
import sys
from flask_socketio import SocketIO

# Ajout du path pour les imports internes
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# --- CONFIGURATION ---
REDIS_URL = os.getenv('REDIS_URL', 'redis://acra-redis:6379/0')
DB_URL = os.getenv('DATABASE_URL', "dbname=acra user=acra_admin password=changeme123 host=postgres")

ZEEK_LOG_DIR = "/app/data/zeek_logs/"
CONN_LOG = os.path.join(ZEEK_LOG_DIR, "conn.log")
SSL_LOG = os.path.join(ZEEK_LOG_DIR, "ssl.log")

print(f"📡 [DEBUG] Connexion au bus Redis : {REDIS_URL}", flush=True)

try:
    # On ajoute le paramètre engineio_logger pour voir les erreurs de transmission
    socket_sender = SocketIO(message_queue=REDIS_URL, engineio_logger=False)
    print("✅ [DEBUG] Socket.IO prêt pour l'émission vers le Dashboard.", flush=True)
except Exception as e:
    print(f"❌ [DEBUG] Erreur Socket.IO : {e}", flush=True)

def get_db_connection():
    while True:
        try:
            conn = psycopg2.connect(DB_URL)
            return conn
        except Exception as e:
            print(f"❌ [DB] Connexion impossible : {e}", flush=True)
            time.sleep(2)

# --- SYSTÈME DE FINGERPRINTING (Identification des types) ---
def classify_device(ip, port, service):
    """Logique heuristique pour identifier le type d'équipement"""
    # 1. Routeurs / Passerelles
    if ip.endswith('.1') or ip.endswith('.254'):
        return 'router'
    
    # 2. Serveurs (Basé sur les ports standards)
    server_ports = {80, 443, 53, 22, 3306, 5432, 8080, 27017}
    if port in server_ports or service in ['http', 'dns', 'ssl', 'ssh', 'mysql', 'postgresql']:
        return 'server'
    
    # 3. Mobiles / IoT (Basé sur les protocoles de découverte)
    if service in ['mdns', 'upnp', 'coap'] or port in [5353, 1900]:
        return 'smartphone'
    
    # 4. Défaut
    return 'computer'

# --- FONCTION D'OBSERVATION ---
def update_assets_observation(cur, data, log_type):
    """Met à jour la visibilité des équipements et leur classification"""
    ip_src = data.get('id.orig_h')
    ip_dst = data.get('id.resp_h')
    if not ip_src: return

    # Déterminer si l'IP source est interne
    is_internal = ip_src.startswith(('192.168.', '10.', '172.16.', '172.31.'))
    asset_type = 'internal' if is_internal else 'external'

    # Identification du type d'appareil
    resp_p = data.get('id.resp_p', 0)
    service = data.get('service', 'unknown')
    
    # On classifie l'IP source si elle est interne, ou l'IP destination
    dev_type = classify_device(ip_src, resp_p, service)

    if log_type == 'conn':
        sent = data.get('orig_bytes', 0) or 0
        recv = data.get('resp_bytes', 0) or 0
        
        # SQL : Mise à jour de l'IP source (Client)
        query = """
            INSERT INTO network_assets (ip_address, asset_type, device_type, total_bytes_sent, total_bytes_received, last_seen, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'online')
            ON CONFLICT (ip_address) DO UPDATE SET
                total_bytes_sent = network_assets.total_bytes_sent + EXCLUDED.total_bytes_sent,
                total_bytes_received = network_assets.total_bytes_received + EXCLUDED.total_bytes_received,
                last_seen = EXCLUDED.last_seen,
                status = 'online',
                device_type = CASE 
                    WHEN network_assets.device_type = 'computer' THEN EXCLUDED.device_type 
                    ELSE network_assets.device_type 
                END;
        """
        cur.execute(query, (ip_src, asset_type, dev_type, sent, recv, datetime.now()))

        # Mise à jour de l'IP destination si elle est interne (Serveur local ?)
        if ip_dst and ip_dst.startswith(('192.168.', '10.')):
            dst_type = classify_device(ip_dst, resp_p, service)
            cur.execute("""
                INSERT INTO network_assets (ip_address, asset_type, device_type, last_seen, status)
                VALUES (%s, 'internal', %s, %s, 'online')
                ON CONFLICT (ip_address) DO UPDATE SET 
                last_seen = EXCLUDED.last_seen, 
                status = 'online',
                device_type = CASE 
                    WHEN network_assets.device_type = 'computer' THEN EXCLUDED.device_type 
                    ELSE network_assets.device_type 
                END;
            """, (ip_dst, dst_type, datetime.now()))

    elif log_type == 'ssl':
        server_name = data.get('server_name')
        if server_name:
            query = """
                UPDATE network_assets 
                SET top_domains = (
                    SELECT jsonb_agg(DISTINCT x)
                    FROM jsonb_array_elements_text(COALESCE(top_domains, '[]'::jsonb) || jsonb_build_array(%s)) AS x
                    WHERE x IS NOT NULL
                ),
                last_seen = %s
                WHERE ip_address = %s;
            """
            cur.execute(query, (server_name, datetime.now(), ip_src))

def stream_zeek_logs():
    print("🚀 [INGESTION] Pipeline ACRA démarré - Mode Classification Active", flush=True)
    conn = get_db_connection()
    # Initialisation de SocketIO pour les futures alertes temps réel
    socket_sender = SocketIO(message_queue=REDIS_URL)

    while True:
        if not os.path.exists(CONN_LOG):
            print(f"⏳ En attente de {CONN_LOG}...", flush=True)
            time.sleep(2)
            continue

        print(f"📖 Analyse des flux dans {CONN_LOG}", flush=True)
        with open(CONN_LOG, "r") as f:
            # Pour traiter l'historique au démarrage, on ne fait pas f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    if not os.path.exists(CONN_LOG):
                        break 
                    time.sleep(0.1)
                    continue

                try:
                    data = json.loads(line)
                    if not isinstance(data, dict): continue

                    with conn.cursor() as cur:
                        # 1. Sauvegarde dans Network Flow (Historique)
                        flow_entry = (
                            datetime.fromtimestamp(data['ts']), data['uid'],
                            data['id.orig_h'], data['id.orig_p'],
                            data['id.resp_h'], data['id.resp_p'],
                            data['proto'], data.get('service', 'unknown'),
                            data.get('orig_bytes', 0) or 0, data.get('resp_bytes', 0) or 0
                        )
                        cur.execute("""
                            INSERT INTO network_flows (ts, uid, source_ip, source_port, dest_ip, dest_port, protocol, service, orig_bytes, resp_bytes)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (uid) DO NOTHING
                        """, flow_entry)

                        # 2. Mise à jour de l'Inventaire (Topologie & Assets)
                        update_assets_observation(cur, data, 'conn')
                        
                        conn.commit()
                        
                        # Log console réduit pour ne pas saturer le terminal
                        if data.get('id.resp_p') in [80, 443]:
                            print(f"🌐 [WEB] {data['id.orig_h']} -> {data['id.resp_h']} ({data.get('service')})", flush=True)

                except Exception as e:
                    print(f"⚠️ [ERREUR INGESTION] : {e}", flush=True)
                    conn.rollback()

            except Exception as e:
                print(f"⚠️ [ERREUR] : {e}", flush=True)

# --- AJOUT INDISPENSABLE : L'appel au démarrage ---
if __name__ == "__main__":
    stream_zeek_logs()