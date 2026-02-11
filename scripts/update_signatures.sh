#!/bin/bash
echo "🚀 [UPDATE-MANAGER] Démarrage..."

# 1. Mise à jour des règles
sudo suricata-update

# 2. Rechargement (On vérifie d'abord si le socket existe)
if [ -S /var/run/suricata/suricata-command.socket ]; then
    echo "♻️ Rechargement des règles..."
    sudo suricatasc -c reload-rules
else
    echo "⚠️ Socket introuvable, redémarrage du service..."
    sudo systemctl restart suricata
fi

# 3. Blacklist Redis (Utilisation forcée du VENV)
echo "📥 Mise à jour Redis..."
/home/grace/Documents/acra/venv/bin/python3 -c "
import requests, redis
try:
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    res = requests.get('https://lists.blocklist.de/lists/all.txt', timeout=10)
    ips = [ip.strip() for ip in res.text.split('\n') if ip.strip()]
    if ips:
        r.delete('blacklist_ips')
        r.sadd('blacklist_ips', *ips)
        print(f'✅ {len(ips)} IPs injectées.')
except Exception as e:
    print(f'❌ Erreur : {e}')
"