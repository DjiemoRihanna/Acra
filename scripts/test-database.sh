cat > scripts/test-database.sh << 'EOF'
#!/bin/bash
# Script de test de connexion à la base de données
# Ce script se rend automatiquement exécutable

# Si le script n'est pas exécutable, on le rend exécutable et on le relance
if [ ! -x "$0" ]; then
    echo "🔧 Configuration des permissions..."
    chmod +x "$0"
    exec "$0" "$@"
fi

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🗄️  TEST BASE DE DONNÉES ACRA${NC}"
echo -e "${BLUE}========================================${NC}"

# Vérifier que le conteneur postgres tourne
if ! docker ps | grep -q acra-postgres; then
    echo -e "${RED}❌ Conteneur acra-postgres non trouvé${NC}"
    exit 1
fi

# Tester la connexion
echo -e "${YELLOW}📡 Test de connexion...${NC}"
if docker exec acra-postgres pg_isready -U acra_admin -d acra >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Connexion réussie${NC}"
else
    echo -e "${RED}❌ Connexion échouée${NC}"
    exit 1
fi

# Lister les tables
echo -e "${YELLOW}📋 Tables dans la base:${NC}"
TABLES=$(docker exec acra-postgres psql -U acra_admin -d acra -t -c "SELECT tablename FROM pg_tables WHERE schemaname='public';")
if [ -z "$TABLES" ]; then
    echo -e "${RED}  Aucune table trouvée${NC}"
else
    echo "$TABLES" | while read table; do
        if [ ! -z "$table" ]; then
            COUNT=$(docker exec acra-postgres psql -U acra_admin -d acra -t -c "SELECT COUNT(*) FROM $table;" | tr -d ' ')
            echo -e "${GREEN}  ✅ $table: $COUNT enregistrements${NC}"
        fi
    done
fi

echo -e "${BLUE}========================================${NC}"
EOF