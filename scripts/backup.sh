cat > scripts/backup.sh << 'EOF'
#!/bin/bash
# Script de sauvegarde complète d'ACRA SOC
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
BLUE='\033[0;34m'
NC='\033[0m'

BACKUP_DIR="data/backups"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/acra_backup_$DATE.tar.gz"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}💾 SAUVEGARDE ACRA SOC${NC}"
echo -e "${BLUE}========================================${NC}"

# Vérifier que le répertoire de backup existe
mkdir -p "$BACKUP_DIR"

# Sauvegarde PostgreSQL
echo -e "${YELLOW}📦 Sauvegarde de la base de données...${NC}"
docker exec acra-postgres pg_dump -U acra_admin acra > "$BACKUP_DIR/acra_db_$DATE.sql"
echo -e "${GREEN}✅ Base de données sauvegardée${NC}"

# Sauvegarde des modèles ML
echo -e "${YELLOW}📦 Sauvegarde des modèles ML...${NC}"
tar -czf "$BACKUP_DIR/ml_models_$DATE.tar.gz" -C data/ml_models . 2>/dev/null || echo "   (pas de modèles ML)"

# Sauvegarde des logs immuables
echo -e "${YELLOW}📦 Sauvegarde des logs immuables...${NC}"
tar -czf "$BACKUP_DIR/immutable_logs_$DATE.tar.gz" -C data/immutable_logs . 2>/dev/null || echo "   (pas de logs immuables)"

# Sauvegarde de la configuration
echo -e "${YELLOW}📦 Sauvegarde de la configuration...${NC}"
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" docker/config/ .env 2>/dev/null

# Création de l'archive complète
echo -e "${YELLOW}📦 Création de l'archive complète...${NC}"
tar -czf "$BACKUP_FILE" \
    -C "$BACKUP_DIR" "acra_db_$DATE.sql" \
    -C "$BACKUP_DIR" "ml_models_$DATE.tar.gz" 2>/dev/null || true \
    -C "$BACKUP_DIR" "immutable_logs_$DATE.tar.gz" 2>/dev/null || true \
    -C "$BACKUP_DIR" "config_$DATE.tar.gz" 2>/dev/null || true

# Nettoyage des fichiers temporaires
rm -f "$BACKUP_DIR/acra_db_$DATE.sql"
rm -f "$BACKUP_DIR/ml_models_$DATE.tar.gz"
rm -f "$BACKUP_DIR/immutable_logs_$DATE.tar.gz"
rm -f "$BACKUP_DIR/config_$DATE.tar.gz"

echo -e "${GREEN}✅ Sauvegarde terminée: $BACKUP_FILE${NC}"
echo -e "${BLUE}========================================${NC}"
EOF