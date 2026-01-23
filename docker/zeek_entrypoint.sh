#!/bin/sh
set -e

echo "[ACRA-ZEEK] Détection des interfaces réseau..."

IFACES=$(ip -o link show up | awk -F': ' '{print $2}' | grep -vE '^lo$|^docker|^br-')

if [ -z "$IFACES" ]; then
  echo "[ACRA-ZEEK] ❌ Aucune interface valide trouvée."
  exit 1
fi

for iface in $IFACES; do
  echo "[ACRA-ZEEK] ▶ Lancement Zeek sur $iface"
  zeek -i "$iface" -C local LogAscii::use_json=T &
done

echo "[ACRA-ZEEK] ✅ Zeek lancé sur toutes les interfaces."
wait
