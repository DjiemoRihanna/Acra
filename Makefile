cat > Makefile << 'EOF'
# Makefile pour ACRA SOC

.PHONY: help install start stop restart logs clean backup restore healthcheck test-db

help:
	@echo "ACRA SOC - Commandes disponibles"
	@echo ""
	@echo "  make install      - Installation complète du système"
	@echo "  make start        - Démarrer les services"
	@echo "  make stop         - Arrêter les services"
	@echo "  make restart      - Redémarrer les services"
	@echo "  make logs         - Voir les logs en temps réel"
	@echo "  make clean        - Nettoyer les conteneurs et volumes"
	@echo "  make backup       - Sauvegarder les données"
	@echo "  make restore      - Restaurer une sauvegarde"
	@echo "  make healthcheck  - Vérifier la santé des services"
	@echo "  make test-db      - Tester la base de données"
	@echo ""

install:
	@./scripts/setup.sh

start:
	@docker-compose up -d

stop:
	@docker-compose down

restart:
	@docker-compose restart

logs:
	@docker-compose logs -f

clean:
	@docker-compose down -v
	@docker system prune -f

backup:
	@./scripts/backup.sh

restore:
	@./scripts/restore.sh

healthcheck:
	@./scripts/healthcheck.sh

test-db:
	@./scripts/test-database.sh
EOF