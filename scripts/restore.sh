cat > scripts/restore.sh << 'EOF'
#!/bin/bash
# Script de restauration d'ACRA SOC
# Ce script se rend automatiquement exécutable

# Si le script n'est pas exécutable, on le rend exécutable et on le relance
if [ ! -x "$0" ]; then
    echo "🔧 Configuration des permissions..."
    chmod +x "$0"
    exec "$0" "$@"
fi

set -e

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

BACKUP_DIR="data/backups"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🔄 RESTAURATION ACRA SOC${NC}"
echo -e "${BLUE}========================================${NC}"

# Lister les backups disponibles
echo -e "${YELLOW}📋 Backups disponibles:${NC}"
BACKUPS=($(ls -1 "$BACKUP_DIR"/acra_backup_*.tar.gz 2>/dev/null | sort -r))

if [ ${#BACKUPS[@]} -eq 0 ]; then
    echo -e "${RED}❌ Aucun backup trouvé dans $BACKUP_DIR${NC}"
    exit 1
fi

for i in "${!BACKUPS[@]}"; do
    SIZE=$(du -h "${BACKUPS[$i]}" | cut -f1)
    echo "   [$((i+1))] $(basename "${BACKUPS[$i]}") ($SIZE)"
done

echo ""
read -p "Choisissez le numéro du backup à restaurer [1-${#BACKUPS[@]}]: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#BACKUPS[@]}" ]; then
    echo -e "${RED}❌ Choix invalide${NC}"
    exit 1
fi

SELECTED_BACKUP="${BACKUPS[$((choice-1))]}"
echo -e "${GREEN}✅ Backup sélectionné: $(basename "$SELECTED_BACKUP")${NC}"

echo -e "${YELLOW}⚠️  Attention: La restauration va écraser les données actuelles.${NC}"
read -p "Confirmer la restauration? (oui/non) " confirm

if [ "$confirm" != "oui" ]; then
    echo -e "${RED}❌ Restauration annulée${NC}"
    exit 0
fi

# Arrêter les services
echo -e "${YELLOW}🛑 Arrêt des services...${NC}"
docker-compose down

# Extraire le backup
echo -e "${YELLOW}📦 Extraction du backup...${NC}"
TEMP_DIR="/tmp/acra_restore_$$"
mkdir -p "$TEMP_DIR"
tar -xzf "$SELECTED_BACKUP" -C "$TEMP_DIR"

# Restaurer la base de données
echo -e "${YELLOW}🗄️  Restauration de la base de données...${NC}"
# Démarrer uniquement postgres
docker-compose up -d postgres
sleep 5
cat "$TEMP_DIR"/*.sql | docker exec -i acra-postgres psql -U acra_admin acra 2>/dev/null || echo "   ⚠️  Erreur restauration DB"

# Restaurer les modèles ML
if [ -f "$TEMP_DIR"/*ml_models*.tar.gz ]; then
    echo -e "${YELLOW}🧠 Restauration des modèles ML...${NC}"
    tar -xzf "$TEMP_DIR"/*ml_models*.tar.gz -C data/ml_models/ 2>/dev/null || true
fi

# Restaurer les logs immuables
if [ -f "$TEMP_DIR"/*immutable_logs*.tar.gz ]; then
    echo -e "${YELLOW}📜 Restauration des logs immuables...${NC}"
    tar -xzf "$TEMP_DIR"/*immutable_logs*.tar.gz -C data/immutable_logs/ 2>/dev/null || true
fi

# Restaurer la configuration
if [ -f "$TEMP_DIR"/*config*.tar.gz ]; then
    echo -e "${YELLOW}⚙️  Restauration de la configuration...${NC}"
    tar -xzf "$TEMP_DIR"/*config*.tar.gz -C . 2>/dev/null || true
fi

# Nettoyage
rm -rf "$TEMP_DIR"

# Redémarrer tous les services
echo -e "${YELLOW}🚀 Redémarrage des services...${NC}"
docker-compose up -d

echo -e "${GREEN}✅ Restauration terminée${NC}"
echo -e "${BLUE}========================================${NC}"
EOF