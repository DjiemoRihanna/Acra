#!/bin/bash

# Couleurs pour la lisibilité
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== Réinitialisation de l'environnement ACRA ===${NC}"
docker-compose down -v
docker-compose up -d --build

echo -e "${BLUE}=== Attente du démarrage de Flask... ===${NC}"
# Attendre que le message "Database Ready" apparaisse dans les logs
until docker logs acra-web 2>&1 | grep -q "Database Ready"; do
  sleep 1
done
echo -e "${GREEN}✅ Serveur prêt !${NC}"

echo -e "\n${BLUE}=== ÉTAPE 1 : Tentative de Login (Phase 1) ===${NC}"
RESPONSE=$(curl -s -i -X POST http://localhost:5000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@acra.local", "password": "Admin@123"}' \
     -c cookies.txt)

if echo "$RESPONSE" | grep -q "202"; then
    echo -e "${GREEN}✅ Phase 1 réussie (202 Accepted)${NC}"
else
    echo -e "${RED}❌ Échec Phase 1${NC}"
    echo "$RESPONSE"
    exit 1
fi

echo -e "\n${BLUE}=== ÉTAPE 2 : Extraction du code MFA depuis les logs ===${NC}"
sleep 2 # Laisser le temps au print de s'afficher
MFA_CODE=$(docker logs acra-web 2>&1 | grep "\[MFA\]" | tail -n 1 | awk -F': ' '{print $2}' | tr -d '\r')

if [ -z "$MFA_CODE" ]; then
    echo -e "${RED}❌ Impossible de trouver le code MFA dans les logs.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Code trouvé : $MFA_CODE${NC}"

echo -e "\n${BLUE}=== ÉTAPE 3 : Validation MFA (Phase 2) ===${NC}"
curl -i -X POST http://localhost:5000/auth/verify-mfa \
     -H "Content-Type: application/json" \
     -d "{\"code\": \"$MFA_CODE\"}" \
     -b cookies.txt -c cookies.txt

echo -e "\n\n${BLUE}=== ÉTAPE 4 : Test de l'accès protégé (RBAC) ===${NC}"
curl -i -X POST http://localhost:5000/api/test-zeek \
     -b cookies.txt

echo -e "\n${GREEN}=== TEST SOC TERMINÉ ===${NC}"

# Exécuter le script avec :
#chmod +x test_soc.sh
#./test_soc.sh

