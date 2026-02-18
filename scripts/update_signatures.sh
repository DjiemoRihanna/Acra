# Vérifier que le fichier existe
ls -la scripts/update_signatures.sh

# Si nécessaire, le créer
cat > scripts/update_signatures.sh << 'EOF'
#!/bin/bash
# Script de mise à jour des signatures Suricata pour ACRA SOC

set -e

echo "[ACRA] 🔄 Mise à jour des signatures Suricata..."

# URLs des règles
declare -A RULE_SOURCES=(
    ["emerging"]="https://rules.emergingthreats.net/open/suricata-7.0.2/emerging.rules.tar.gz"
    ["etopen"]="https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
    ["sslbl"]="https://sslbl.abuse.ch/blacklist/sslbl.rules"
    ["ja3"]="https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules"
)

# Répertoires
RULES_DIR="/var/lib/suricata/rules"
TEMP_DIR="/tmp/suricata-rules"
ACRA_RULES_DIR="/etc/suricata/acra-rules"

mkdir -p "$RULES_DIR" "$TEMP_DIR" "$ACRA_RULES_DIR"

# Téléchargement et extraction des règles
for source in "${!RULE_SOURCES[@]}"; do
    url="${RULE_SOURCES[$source]}"
    echo "[ACRA] 📥 Téléchargement: $source"
    
    if [[ $url == *.tar.gz ]]; then
        wget -qO- "$url" | tar xz -C "$TEMP_DIR"
        find "$TEMP_DIR" -name "*.rules" -exec cp {} "$RULES_DIR/" \;
    else
        wget -q "$url" -O "$RULES_DIR/${source}.rules"
    fi
done

# Règles personnalisées ACRA (coupe-circuit)
cat > "$ACRA_RULES_DIR/acra-critical.rules" << 'EOF'
# Règles critiques ACRA - Coupe-circuit (priorité 10)

# Détection de scans de ports agressifs
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ACRA - Port Scan Detected"; \
    flow:stateless; threshold:type both, track by_src, count 50, seconds 10; \
    priority:10; classtype:attempted-recon; sid:1000001; rev:1;)

# Détection de brute force SSH
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ACRA - SSH Brute Force"; \
    flow:to_server,established; content:"SSH"; nocase; \
    threshold:type both, track by_src, count 10, seconds 60; \
    priority:10; classtype:attempted-dos; sid:1000002; rev:1;)

# Détection de scan de ports furtif (SYN stealth scan)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ACRA - SYN Stealth Scan"; \
    flags:S,12; threshold:type both, track by_src, count 20, seconds 5; \
    priority:10; classtype:attempted-recon; sid:1000007; rev:1;)
EOF

echo "[ACRA] ✅ Signatures mises à jour"
EOF

# Rendre exécutable
chmod +x scripts/update_signatures.sh