#!/bin/bash
# Entrypoint pour Suricata ACRA
# Ce script est déjà exécutable grâce au Dockerfile

set -e

echo "[ACRA-SURICATA] 🚀 Démarrage du service..."

# Mise à jour des signatures au démarrage
if [ "$UPDATE_SIGNATURES" = "true" ]; then
    echo "[ACRA-SURICATA] 🔄 Mise à jour des signatures..."
    /usr/local/bin/update-signatures.sh
fi

# Création du fichier eve.json s'il n'existe pas
mkdir -p /var/log/suricata
touch /var/log/suricata/eve.json
chmod 666 /var/log/suricata/eve.json

# Lancement de Suricata
echo "[ACRA-SURICATA] 🎯 Suricata en écoute sur $INTERFACE"
exec suricata -c /etc/suricata/suricata.yaml \
              -i ${INTERFACE:-eth0} \
              --set unix-command.enabled=true \
              --set unix-command.filename=/var/run/suricata/suricata-command.socket \
              -v