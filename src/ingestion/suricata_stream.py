import json
import time
import os

EVE_PATH = "/var/log/suricata/eve.json"

def stream_alerts():
    print(f"📡 [INGESTION] Lecture en temps réel de {EVE_PATH}...")
    
    if not os.path.exists(EVE_PATH):
        print(f"❌ Erreur : {EVE_PATH} introuvable.")
        return

    with open(EVE_PATH, 'r') as f:
        # Aller à la fin du fichier pour ne lire que les nouvelles alertes
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
                
            try:
                data = json.loads(line)
                # On accepte 'alert' pour les attaques et 'anomaly' pour les scans
                if data.get("event_type") in ["alert", "anomaly"]:
                    yield data
            except json.JSONDecodeError:
                continue