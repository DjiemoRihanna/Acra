#!/bin/bash
# test-database.sh
# Teste la connexion et la structure de la base de données

set -e

echo "🧪 Test de la base de données ACRA..."

# Vérifier que Docker est en cours
if ! docker-compose ps | grep -q "acra-postgres"; then
    echo "❌ PostgreSQL n'est pas démarré"
    echo "💡 Lancez: docker-compose up -d postgres"
    exit 1
fi

# Test de connexion
echo "1. Test de connexion à PostgreSQL..."
if docker-compose exec -T postgres pg_isready -U acra_admin; then
    echo "✅ PostgreSQL est accessible"
else
    echo "❌ Impossible de se connecter à PostgreSQL"
    exit 1
fi

# Vérifier que la base existe
echo "2. Vérification de la base 'acra'..."
if docker-compose exec -T postgres psql -U acra_admin -d acra -c "\q" 2>/dev/null; then
    echo "✅ Base 'acra' existe"
else
    echo "❌ Base 'acra' n'existe pas"
    echo "💡 Réinitialisez: docker-compose down -v && docker-compose up -d postgres"
    exit 1
fi

# Vérifier les tables
echo "3. Vérification des tables..."
docker-compose exec -T postgres psql -U acra_admin -d acra -c "
    SELECT 
        table_name,
        (SELECT COUNT(*) FROM acra.\"\${table_name}\") as row_count
    FROM information_schema.tables 
    WHERE table_schema = 'acra' 
    ORDER BY table_name;
"

# Test des données admin
echo "4. Vérification de l'utilisateur admin..."
docker-compose exec -T postgres psql -U acra_admin -d acra -c "
    SELECT 
        email, 
        role, 
        is_active,
        created_at::date
    FROM acra.users 
    WHERE email = 'admin@acra.local';
"

echo ""
echo "🎉 Tests de base de données terminés avec succès!"
echo "📊 Pour explorer la BD: docker-compose exec postgres psql -U acra_admin -d acra"
