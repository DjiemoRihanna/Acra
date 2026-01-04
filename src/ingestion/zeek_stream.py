import json
import os
import time
import psycopg2
from datetime import datetime

# Config via variables d'environnement (.env)
DB_URL = os.getenv('DATABASE_URL')
LOG_PATH = "/app/ingestion/logs/conn.log"

def stream_to_db():
    print(f"📡 Démarrage de l'ingestion des flux Zeek...")
    
    # Connexion persistante
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    while True:
        if not os.path.exists(LOG_PATH):
            time.sleep(1)
            continue

        with open(LOG_PATH, 'r') as f:
            # Aller à la fin du fichier pour les nouveaux logs seulement
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                try:
                    data = json.loads(line)
                    # Mapping JSON Zeek -> SQL ACRA
                    cur.execute("""
                        INSERT INTO network_flows (ts, uid, source_ip, source_port, dest_ip, dest_port, protocol, service, orig_bytes, resp_bytes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        datetime.fromtimestamp(data['ts']), data['uid'],
                        data['id.orig_h'], data['id.orig_p'],
                        data['id.resp_h'], data['id.resp_p'],
                        data['proto'], data.get('service', 'unknown'),
                        data.get('orig_bytes', 0), data.get('resp_bytes', 0)
                    ))
                    conn.commit()
                except Exception as e:
                    print(f"❌ Erreur parsing/insert: {e}")
                    conn.rollback()

if __name__ == "__main__":
    stream_to_db()