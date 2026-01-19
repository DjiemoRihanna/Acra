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
                    print("✅ [DB] Toutes les tables sont prêtes. Lancement.", flush=True)
                    return True
                else:
                    time.sleep(3)
        except Exception as e:
            time.sleep(2)

# --- SYSTÈME DE FINGERPRINTING AUTOMATIQUE (Zéro Hardcoding) ---
def classify_device(ip, port, service, is_internal=True, is_receiver=False):
    """Identifie l'équipement par son comportement réel sur le réseau."""
    
    # 1. Identification CLOUD (IP Publique)
    if not is_internal:
        return 'cloud'

    # 2. Identification ROUTER / GATEWAY (Comportementale)
    # En environnement réel, l'équipement qui gère le DNS ou le DHCP local est le routeur
    if is_receiver and (service in ['dns', 'dhcp'] or port in [53, 67, 68]):
        return 'router'
    
    # 3. Identification SERVEUR (Bases de données, SSH, SMB)
    infra_ports = {22, 3306, 5432, 8080, 27017, 6379, 9000, 445}
    infra_services = ['ssh', 'mysql', 'postgresql', 'redis', 'smb', 'rpc']
    if is_receiver and (port in infra_ports or service in infra_services):
        return 'server'
    
    # 4. Identification IMPRIMANTE (Protocoles de print)
    if is_receiver and (port in [9100, 631, 515]):
        return 'printer'
    
    # 5. Identification SMARTPHONE / IOT (Protocoles mobiles & Broadcast)
    if service in ['mdns', 'upnp', 'coap'] or port in [5353, 1900]:
        return 'smartphone'
    
    # 6. Par défaut, ordinateur client
    return 'computer'

# --- FONCTION D'OBSERVATION ---
def update_assets_observation(cur, data, log_type):
    """Analyse bidirectionnelle : Source et Destination sont traitées."""
    ip_src = data.get('id.orig_h')
    ip_dst = data.get('id.resp_h')
    if not ip_src: return

    resp_p = data.get('id.resp_p', 0)
    service = data.get('service', 'unknown')
    
    # Plages privées RFC1918 pour auto-détection interne/externe
    private_nets = ('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                    '172.2', '172.30.', '172.31.', '127.')

    # Traitement des deux acteurs de la connexion
    for ip, is_receiver in [(ip_src, False), (ip_dst, True)]:
        if not ip: continue
        
        is_internal = ip.startswith(private_nets)
        asset_type = 'internal' if is_internal else 'external'
        dev_type = classify_device(ip, resp_p, service, is_internal=is_internal, is_receiver=is_receiver)

        # Les stats de trafic sont attribuées à l'initiateur (orig) pour éviter les doublons
        sent = data.get('orig_bytes', 0) or 0 if not is_receiver else 0
        recv = data.get('resp_bytes', 0) or 0 if not is_receiver else 0

        # SQL UPSERT avec hiérarchie de types : on ne dégrade pas un serveur/routeur en simple PC
        cur.execute("""
            INSERT INTO network_assets (ip_address, asset_type, device_type, total_bytes_sent, total_bytes_received, last_seen, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'online')
            ON CONFLICT (ip_address) DO UPDATE SET
                total_bytes_sent = network_assets.total_bytes_sent + EXCLUDED.total_bytes_sent,
                total_bytes_received = network_assets.total_bytes_received + EXCLUDED.total_bytes_received,
                last_seen = EXCLUDED.last_seen,
                status = 'online',
                device_type = CASE 
                    WHEN network_assets.device_type IN ('server', 'router', 'printer', 'cloud') THEN network_assets.device_type 
                    ELSE EXCLUDED.device_type 
                END;
        """, (ip, asset_type, dev_type, sent, recv, datetime.now()))

    if log_type == 'ssl':
        server_name = data.get('server_name')
        if server_name:
            cur.execute("""
                UPDATE network_assets 
                SET top_domains = (
                    SELECT jsonb_agg(DISTINCT x)
                    FROM jsonb_array_elements_text(COALESCE(top_domains, '[]'::jsonb) || jsonb_build_array(%s)) AS x
                    WHERE x IS NOT NULL
                ),
                last_seen = %s
                WHERE ip_address = %s;
            """, (server_name, datetime.now(), ip_src))

def stream_zeek_logs():
    print("🚀 [INGESTION] Pipeline ACRA démarré - Détection Automatique Intelligente", flush=True)
    conn = get_db_connection()
    wait_for_tables(conn)
    
    while True:
        if not os.path.exists(CONN_LOG):
            time.sleep(2)
            continue

        with open(CONN_LOG, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    if not os.path.exists(CONN_LOG): break 
                    time.sleep(0.1)
                    continue

                try:
                    data = json.loads(line)
                    with conn.cursor() as cur:
                        # 1. Flux brut
                        cur.execute("""
                            INSERT INTO network_flows (ts, uid, source_ip, source_port, dest_ip, dest_port, protocol, service, orig_bytes, resp_bytes)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (uid) DO NOTHING
                        """, (datetime.fromtimestamp(data['ts']), data['uid'], data['id.orig_h'], data['id.orig_p'],
                              data['id.resp_h'], data['id.resp_p'], data['proto'], data.get('service', 'unknown'),
                              data.get('orig_bytes', 0) or 0, data.get('resp_bytes', 0) or 0))

                        # 2. Identification automatique
                        update_assets_observation(cur, data, 'conn')
                        conn.commit()

                except json.JSONDecodeError: continue
                except Exception as e:
                    print(f"⚠️ [ERREUR INGESTION] : {e}", flush=True)
                    conn.rollback()

# --- AJOUT INDISPENSABLE : L'appel au démarrage ---
if __name__ == "__main__":
    stream_zeek_logs()