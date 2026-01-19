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

def get_db_connection():
    """Établit la connexion initiale à Postgres avec retry."""
    while True:
        try:
            conn = psycopg2.connect(DB_URL)
            return conn
        except Exception as e:
            print(f"❌ [DB] Connexion impossible : {e}", flush=True)
            time.sleep(2)

def wait_for_tables(conn):
    """Attend que les tables soient créées par le service Web avant de continuer."""
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
                    print("✅ [DB] Toutes les tables sont prêtes. Lancement de l'ingestion.", flush=True)
                    return True
                else:
                    print(f"⏳ [DB] Attente des tables : {', '.join(missing_tables)}...", flush=True)
                    time.sleep(3)
        except Exception as e:
            print(f"⚠️ [DB] Erreur lors de la vérification des tables : {e}", flush=True)
            time.sleep(2)

# --- SYSTÈME DE FINGERPRINTING (Identification des types) ---
def classify_device(ip, port, service, is_receiver=False):
    """Logique stabilisée pour différencier les serveurs des clients web."""
    # 1. Identification immédiate par l'IP (Passerelle/Router)
    if ip.endswith('.1') or ip.endswith('.254'):
        return 'router'
    
    # 2. Identification par services d'infrastructure (Vrais serveurs)
    # UN appareil n'est un serveur que s'il est la DESTINATION (is_receiver) d'un port infra
    infra_ports = {53, 22, 3306, 5432, 8080, 27017}
    infra_services = ['dns', 'ssh', 'mysql', 'postgresql']
    
    if is_receiver and (port in infra_ports or service in infra_services):
        return 'server'
    
    # 3. Objets connectés / Mobiles
    if service in ['mdns', 'upnp', 'coap'] or port in [5353, 1900]:
        return 'smartphone'
    
    # 4. Par défaut, si c'est du trafic web standard (80/443), c'est un ordinateur client
    return 'computer'

# --- FONCTION D'OBSERVATION ---
def update_assets_observation(cur, data, log_type):
    """Met à jour la visibilité des équipements et leur classification"""
    ip_src = data.get('id.orig_h')
    ip_dst = data.get('id.resp_h')
    if not ip_src: return

    is_internal = ip_src.startswith(('192.168.', '10.', '172.16.', '172.31.'))
    asset_type = 'internal' if is_internal else 'external'

    resp_p = data.get('id.resp_p', 0)
    service = data.get('service', 'unknown')
    
    # Correction : On précise que la source est l'initiateur (pas le receveur)
    dev_type = classify_device(ip_src, resp_p, service, is_receiver=False)

    if log_type == 'conn':
        sent = data.get('orig_bytes', 0) or 0
        recv = data.get('resp_bytes', 0) or 0
        
        query = """
            INSERT INTO network_assets (ip_address, asset_type, device_type, total_bytes_sent, total_bytes_received, last_seen, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'online')
            ON CONFLICT (ip_address) DO UPDATE SET
                total_bytes_sent = network_assets.total_bytes_sent + EXCLUDED.total_bytes_sent,
                total_bytes_received = network_assets.total_bytes_received + EXCLUDED.total_bytes_received,
                last_seen = EXCLUDED.last_seen,
                status = 'online',
                device_type = CASE 
                    WHEN network_assets.device_type IN ('server', 'router') THEN network_assets.device_type 
                    ELSE EXCLUDED.device_type 
                END;
        """
        cur.execute(query, (ip_src, asset_type, dev_type, sent, recv, datetime.now()))

        if ip_dst and ip_dst.startswith(('192.168.', '10.', '172.')):
            # Correction : L'IP destination est celle qui reçoit (is_receiver=True)
            dst_type = classify_device(ip_dst, resp_p, service, is_receiver=True)
            cur.execute("""
                INSERT INTO network_assets (ip_address, asset_type, device_type, last_seen, status)
                VALUES (%s, 'internal', %s, %s, 'online')
                ON CONFLICT (ip_address) DO UPDATE SET 
                    last_seen = EXCLUDED.last_seen, 
                    status = 'online',
                    device_type = CASE 
                        WHEN network_assets.device_type IN ('server', 'router') THEN network_assets.device_type 
                        ELSE EXCLUDED.device_type 
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
    # ATTENTE CRUCIALE DES TABLES
    wait_for_tables(conn)
    
    socket_sender = SocketIO(message_queue=REDIS_URL)

    while True:
        if not os.path.exists(CONN_LOG):
            print(f"⏳ En attente de {CONN_LOG}...", flush=True)
            time.sleep(2)
            continue

        print(f"📖 Analyse des flux dans {CONN_LOG}", flush=True)
        with open(CONN_LOG, "r") as f:
            # On se place à la fin du fichier pour ne traiter que les nouveaux logs
            f.seek(0, os.SEEK_END)
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

                        update_assets_observation(cur, data, 'conn')
                        conn.commit()
                        
                        if data.get('id.resp_p') in [80, 443]:
                            print(f"🌐 [WEB] {data['id.orig_h']} -> {data['id.resp_h']} ({data.get('service')})", flush=True)

                except json.JSONDecodeError:
                    # Ignore les lignes tronquées pendant que Zeek écrit
                    continue
                except Exception as e:
                    print(f"⚠️ [ERREUR INGESTION] : {e}", flush=True)
                    conn.rollback()

# --- AJOUT INDISPENSABLE : L'appel au démarrage ---
if __name__ == "__main__":
    stream_zeek_logs()