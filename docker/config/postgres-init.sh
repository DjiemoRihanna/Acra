#!/bin/bash
# postgres-init.sh
# Initialisation de PostgreSQL pour ACRA

set -e

echo "🔧 Initialisation de la base de données ACRA..."

# Attendre que PostgreSQL soit prêt
until pg_isready -U "$POSTGRES_USER" -h localhost; do
    sleep 2
    echo "⏳ En attente de PostgreSQL..."
done

echo "✅ PostgreSQL est prêt"

# Créer la base si elle n'existe pas
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres <<-EOSQL
    SELECT 'CREATE DATABASE $POSTGRES_DB'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB')\gexec
    
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;
EOSQL

echo "✅ Base de données '$POSTGRES_DB' vérifiée/créée"

# Exécuter le schéma
echo "📦 Application du schéma ACRA..."
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/schema.sql

echo "🎉 Initialisation terminée avec succès!"
