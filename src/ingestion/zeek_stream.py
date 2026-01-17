import eventlet
# DOIT être la toute première ligne
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

try:
    from src.core.event_bus import bus
except ImportError:
    bus = None

# --- CONFIGURATION ---
REDIS_URL = os.getenv('REDIS_URL', 'redis://acra-redis:6379/0')
DB_URL = os.getenv('DATABASE_URL', "dbname=acra user=acra_admin password=changeme123 host=postgres")
ZEEK_LOG_PATH = "/app/data/zeek_logs/conn.log"

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
            print(f"❌ [DB] Connexion impossible, nouvelle tentative... ({e})", flush=True)
            time.sleep(2)

def flush_to_db(conn, buffer):
    if not buffer:
        return
    query = """
        INSERT INTO network_flows (ts, uid, source_ip, source_port, dest_ip, dest_port, protocol, service, orig_bytes, resp_bytes)
        VALUES %s ON CONFLICT (uid) DO NOTHING
    """
    try:
        with conn.cursor() as cur:
            execute_values(cur, query, buffer)
            conn.commit()
            print(f"📦 [DB] {len(buffer)} flux sauvegardés.", flush=True)
    except Exception as e:
        print(f"❌ [DB] Erreur insertion : {e}", flush=True)
        conn.rollback()

def stream_zeek_logs():
    print("🚀 [INGESTION] Pipeline ACRA démarré (Mode Stable)", flush=True)
    conn = get_db_connection()
    batch_size = 10 
    buffer = []

    while not os.path.exists(ZEEK_LOG_PATH):
        print(f"⏳ [FILE] En attente de : {ZEEK_LOG_PATH} ...", flush=True)
        time.sleep(2)

    with open(ZEEK_LOG_PATH, "r") as f:
        # ON VA À LA FIN DU FICHIER pour ne traiter que le "vrai" temps réel
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                # Si rien à lire, on vide quand même le buffer s'il contient des données
                if buffer:
                    flush_to_db(conn, buffer)
                    buffer = []
                time.sleep(0.1)
                continue

            try:
                data = json.loads(line)
                raw_vol = (data.get('orig_bytes') or 0) + (data.get('resp_bytes') or 0)
                vol_mo = round(raw_vol / (1024 * 1024), 4)

                current_time = datetime.now().strftime('%H:%M:%S')
                
                # ÉMISSION VERS REDIS -> DASHBOARD
                socket_sender.emit('update_graph', {
                    'volume': vol_mo if vol_mo > 0 else 0.001
                }, namespace='/')
                
                print(f"🔥 [LIVE] {current_time} | {vol_mo} Mo envoyés", flush=True)

                flow_entry = (
                    datetime.fromtimestamp(data['ts']), data['uid'],
                    data['id.orig_h'], data['id.orig_p'],
                    data['id.resp_h'], data['id.resp_p'],
                    data['proto'], data.get('service', 'unknown'),
                    data.get('orig_bytes', 0), data.get('resp_bytes', 0)
                )
                buffer.append(flow_entry)

                if len(buffer) >= batch_size:
                    flush_to_db(conn, buffer)
                    buffer = []

            except Exception as e:
                print(f"⚠️ [ERREUR] : {e}", flush=True)

# --- AJOUT INDISPENSABLE : L'appel au démarrage ---
if __name__ == "__main__":
    try:
        stream_zeek_logs()
    except KeyboardInterrupt:
        print("\n🛑 Arrêt du streamer.")
        sys.exit(0)