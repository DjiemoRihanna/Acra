cat > scripts/healthcheck.sh << 'EOF'
#!/bin/bash
# Script de vérification de santé des services ACRA
# Ce script se rend automatiquement exécutable

# Si le script n'est pas exécutable, on le rend exécutable et on le relance
if [ ! -x "$0" ]; then
    echo "🔧 Configuration des permissions..."
    chmod +x "$0"
    exec "$0" "$@"
fi

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🔍 HEALTHCHECK ACRA SOC${NC}"
echo -e "${BLUE}========================================${NC}"

# Vérifier que Docker est en cours d'exécution
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker n'est pas en cours d'exécution${NC}"
    exit 1
fi

# Services à vérifier
SERVICES=("postgres" "redis" "zeek" "web" "zeek-streamer" "suricata" "suricata-streamer" "scapy-capture" "ml-service")
STATUS=0

for service in "${SERVICES[@]}"; do
    CONTAINER="acra-$service"
    if [ "$service" = "ml-service" ]; then
        CONTAINER="acra-ml"
    fi
    
    if docker ps | grep -q "$CONTAINER"; then
        # Récupérer l'uptime
        UPTIME=$(docker inspect --format='{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null | xargs -I{} date -d {} +"%d/%m/%Y %H:%M:%S")
        echo -e "${GREEN}✅ $service: en cours d'exécution (depuis $UPTIME)${NC}"
    else
        if docker ps -a | grep -q "$CONTAINER"; then
            echo -e "${RED}❌ $service: arrêté${NC}"
        else
            echo -e "${RED}❌ $service: non trouvé${NC}"
        fi
        STATUS=1
    fi
done

echo -e "${BLUE}----------------------------------------${NC}"

# Vérifier les logs récents pour les erreurs
echo -e "${YELLOW}📋 Dernières erreurs dans les logs:${NC}"
for service in "${SERVICES[@]}"; do
    CONTAINER="acra-$service"
    if [ "$service" = "ml-service" ]; then
        CONTAINER="acra-ml"
    fi
    
    if docker ps | grep -q "$CONTAINER"; then
        ERRORS=$(docker logs --tail 50 "$CONTAINER" 2>&1 | grep -i "error\|exception\|traceback" | tail -3)
        if [ ! -z "$ERRORS" ]; then
            echo -e "${YELLOW}  $service:${NC}"
            echo "$ERRORS" | sed 's/^/    /'
        fi
    fi
done

echo -e "${BLUE}========================================${NC}"

# Vérifier les ports exposés
echo -e "${YELLOW}🔌 Ports exposés:${NC}"
if netstat -tlnp 2>/dev/null | grep -q ":5000"; then
    echo -e "${GREEN}  ✅ Port 5000: Web interface${NC}"
else
    echo -e "${RED}  ❌ Port 5000: non accessible${NC}"
fi

echo -e "${BLUE}========================================${NC}"

# Vérifier l'API
if curl -s http://localhost:5000/api/system/health >/dev/null 2>&1; then
    echo -e "${GREEN}✅ API système: accessible${NC}"
else
    echo -e "${RED}❌ API système: non accessible${NC}"
fi

echo -e "${BLUE}========================================${NC}"

if [ $STATUS -eq 0 ]; then
    echo -e "${GREEN}✅ Tous les services sont opérationnels${NC}"
else
    echo -e "${RED}❌ Certains services sont en erreur${NC}"
fi

exit $STATUS
EOF