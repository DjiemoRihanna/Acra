cat > scripts/setup.sh << 'EOF'
#!/bin/bash
# Script d'installation initiale d'ACRA SOC
# Ce script se rend automatiquement exécutable

# Si le script n'est pas exécutable, on le rend exécutable et on le relance
if [ ! -x "$0" ]; then
    echo "🔧 Configuration des permissions..."
    chmod +x "$0"
    exec "$0" "$@"
fi

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🔧 INSTALLATION D'ACRA SOC${NC}"
echo -e "${BLUE}========================================${NC}"

# Vérifier que Docker est installé
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker n'est pas installé${NC}"
    echo "Pour installer Docker: https://docs.docker.com/engine/install/"
    exit 1
fi
echo -e "${GREEN}✅ Docker détecté${NC}"

# Vérifier la version de Docker
docker_version=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
echo "   Version: $docker_version"

# Vérifier que docker-compose est installé
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ docker-compose n'est pas installé${NC}"
    echo "Pour installer docker-compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✅ docker-compose détecté${NC}"

# Vérifier la version de docker-compose
compose_version=$(docker-compose --version | cut -d ' ' -f4 | cut -d ',' -f1)
echo "   Version: $compose_version"

echo -e "${BLUE}----------------------------------------${NC}"

# Créer le fichier .env s'il n'existe pas
if [ ! -f .env ]; then
    echo -e "${YELLOW}📝 Création du fichier .env à partir de .env.example${NC}"
    cp .env.example .env
    echo -e "${GREEN}✅ Fichier .env créé${NC}"
    echo -e "${YELLOW}⚠️  Veuillez éditer le fichier .env pour personnaliser votre configuration${NC}"
    echo "   (notamment les clés API AbuseIPDB et AlienVault si vous en avez)"
else
    echo -e "${GREEN}✅ Fichier .env existant${NC}"
fi

echo -e "${BLUE}----------------------------------------${NC}"

# Créer les répertoires de données
echo -e "${YELLOW}📁 Création des répertoires de données...${NC}"
mkdir -p data/zeek_logs data/suricata_logs data/pgdata data/ml_models data/immutable_logs data/backups
mkdir -p backups/audit_logs
echo -e "${GREEN}✅ Répertoires créés${NC}"

# Ajuster les permissions
chmod -R 755 data backups 2>/dev/null || true

echo -e "${BLUE}----------------------------------------${NC}"

# Détection automatique du réseau
echo -e "${YELLOW}🌐 Détection automatique du réseau...${NC}"
if python3 -c "import netifaces" 2>/dev/null; then
    INTERFACE=$(python3 -c "from src.utils.network_utils import get_soc_interface; print(get_soc_interface())" 2>/dev/null || echo "eth0")
    IP=$(python3 -c "from src.utils.network_utils import get_soc_ip; print(get_soc_ip())" 2>/dev/null || echo "127.0.0.1")
    RANGE=$(python3 -c "from src.utils.network_utils import get_network_range; print(get_network_range())" 2>/dev/null || echo "192.168.1.0/24")
    
    echo -e "   Interface détectée: ${GREEN}$INTERFACE${NC}"
    echo -e "   IP détectée: ${GREEN}$IP${NC}"
    echo -e "   Plage détectée: ${GREEN}$RANGE${NC}"
    
    # Mettre à jour .env avec la plage détectée si elle n'est pas déjà définie
    if grep -q "^NETWORK_RANGE=$" .env; then
        sed -i "s|^NETWORK_RANGE=$|NETWORK_RANGE=$RANGE|" .env
        echo -e "${GREEN}✅ Plage réseau mise à jour dans .env${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Module netifaces non disponible, détection automatique désactivée${NC}"
    echo "   Installez netifaces: pip install netifaces"
fi

echo -e "${BLUE}----------------------------------------${NC}"

# Vérifier les fichiers de configuration Suricata
if [ ! -f "docker/config/suricata.yaml" ]; then
    echo -e "${YELLOW}⚠️  Fichier suricata.yaml manquant, création d'un fichier par défaut...${NC}"
    mkdir -p docker/config
    cat > docker/config/suricata.yaml << 'YAML'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
YAML
    echo -e "${GREEN}✅ Fichier suricata.yaml créé${NC}"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🚀 Lancement de l'installation...${NC}"
echo -e "${BLUE}========================================${NC}"

# Télécharger les images Docker
echo -e "${YELLOW}📥 Téléchargement des images Docker...${NC}"
docker-compose pull

# Construire les images manquantes
echo -e "${YELLOW}🔨 Construction des images...${NC}"
docker-compose build

# Démarrer les services
echo -e "${YELLOW}🚀 Démarrage des services...${NC}"
docker-compose up -d

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✅ ACRA SOC installé avec succès !${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "🌐 Accédez à l'interface: ${GREEN}http://localhost:$(grep WEB_PORT .env | cut -d= -f2)${NC}"
echo -e "📊 Topologie réseau: ${GREEN}http://localhost:$(grep WEB_PORT .env | cut -d= -f2)/network/topology${NC}"
echo -e "⚠️  Centre d'alertes: ${GREEN}http://localhost:$(grep WEB_PORT .env | cut -d= -f2)/alerts/list${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Pour voir les logs: ${YELLOW}docker-compose logs -f${NC}"
echo -e "Pour arrêter: ${YELLOW}docker-compose down${NC}"
echo -e "Pour redémarrer: ${YELLOW}docker-compose restart${NC}"
echo -e "${BLUE}========================================${NC}"
EOF