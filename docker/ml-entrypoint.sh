#!/bin/bash
# Entrypoint pour le service ML ACRA

set -e

echo "[ACRA-ML] 🚀 Démarrage du service Machine Learning..."

# Attendre que la DB soit prête
python -c "
import time
import psycopg2
import os

db_url = os.getenv('DATABASE_URL', 'postgresql://acra_admin:changeme123@localhost:5432/acra')
for i in range(30):
    try:
        conn = psycopg2.connect(db_url)
        conn.close()
        print('[ACRA-ML] ✅ Base de données disponible')
        break
    except Exception as e:
        print(f'[ACRA-ML] ⏳ Attente DB... ({i+1}/30)')
        time.sleep(2)
"

# Démarrer le service ML (trainer en arrière-plan)
echo "[ACRA-ML] 🧠 Démarrage du moteur ML..."
python -u src/ml/trainer.py &

# Garder le conteneur en vie
wait