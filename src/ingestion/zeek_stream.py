import json
import os
import time
import psycopg2
from psycopg2.extras import execute_values
import redis
from datetime import datetime
from src.core.event_bus import bus  # Import de ton bus d'événements

# Configuration via environnement
DB_URL = os.getenv('DATABASE_URL', "dbname=acra user=acra_admin password=acra_pass host=postgres")
ZEEK_LOG_PATH = "/app/data/zeek_logs/conn.log"

def get_db_connection():
    """Gère la reconnexion automatique à PostgreSQL"""
    while True:
        try:
            conn = psycopg2.connect(DB_URL)
            return conn
        except Exception as e:
            print(f"❌ [DB] Connexion impossible, nouvelle tentative dans 2s... ({e})")
            time.sleep(2)

def flush_to_db(conn, buffer):
    """Insertion groupée (Bulk Insert) pour optimiser les performances"""
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
            print(f"✅ [DB] Batch de {len(buffer)} flux insérés.")
    except Exception as e:
        print(f"❌ [DB] Erreur lors de l'insertion : {e}")
        conn.rollback()

def stream_zeek_logs():
    print("📡 [INGESTION] Démarrage du pipeline ACRA (Itération 1)...")
    
    conn = get_db_connection()
    batch_size = 50
    buffer = []

    # 1. Attente de la sonde Zeek
    while not os.path.exists(ZEEK_LOG_PATH):
        print(f"⏳ En attente du fichier log : {ZEEK_LOG_PATH} ...")
        time.sleep(2)

    try:
        with open(ZEEK_LOG_PATH, "r") as f:
            # On commence à la fin du fichier (mode tail -f)
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                
                # Si pas de nouvelle ligne, on vide le buffer si nécessaire
                if not line:
                    if buffer:
                        flush_to_db(conn, buffer)
                        buffer = []
                    time.sleep(0.1) # Ultra-réactif pour respecter les < 2s
                    continue

                try:
                    data = json.loads(line)
                    
                    # 2. Préparation pour SQL
                    flow_entry = (
                        datetime.fromtimestamp(data['ts']),
                        data['uid'],
                        data['id.orig_h'],
                        data['id.orig_p'],
                        data['id.resp_h'],
                        data['id.resp_p'],
                        data['proto'],
                        data.get('service', 'unknown'),
                        data.get('orig_bytes', 0),
                        data.get('resp_bytes', 0)
                    )
                    buffer.append(flow_entry)

                    # 3. Notification TEMPS RÉEL via le Bus (pour Membre C)
                    bus.publish_flow({
                        'src': data['id.orig_h'],
                        'dst': data['id.resp_h'],
                        'proto': data['proto'],
                        'service': data.get('service', '-')
                    })

                    # 4. Insertion par lot
                    if len(buffer) >= batch_size:
                        flush_to_db(conn, buffer)
                        buffer = []

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"⚠️ Erreur traitement ligne : {e}")
                    # En cas d'erreur DB, on recrée la connexion
                    if conn.closed:
                        conn = get_db_connection()

    except KeyboardInterrupt:
        print("\n🛑 Arrêt du pipeline, sauvegarde des derniers flux...")
        if buffer:
            flush_to_db(conn, buffer)
        conn.close()

if __name__ == "__main__":
    stream_zeek_logs()