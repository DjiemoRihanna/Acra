# ACRA - Apprentissage Comportemental Réseau Autonome

## Description
Système NDR (Network Detection and Response) intelligent pour la sécurité réseau.

## Installation
```bash
# 1. Cloner le projet
git clone <url>
cd acra-network-defense

# 2. Configurer l'environnement
cp .env.example .env
# Éditer .env avec vos configurations

# 3. Démarrer avec Docker
docker-compose up --build

# 4. Accéder à l'interface
# http://localhost:5000


acra/                                  # RACINE DU PROJET
│
├── 📄 .gitignore                     # Fichiers ignorés par Git
├── 📄 .dockerignore                  # Fichiers ignorés par Docker
├── 📄 .gitlab-ci.yml                 # Pipeline CI/CD GitLab (3 stages)
├── 📄 docker-compose.yml             # Configuration Docker (tous services)
├── 📄 requirements.txt               # Dépendances Python
├── 📄 README.md                      # Documentation projet
├── 📄 CHANGELOG.md                   # Journal des modifications
├── 📄 Makefile                       # Commandes utiles (make install, make dev)
├── 📄 pyproject.toml                 # Configuration Python moderne
├── 📄 .env.example                   # Variables d'environnement (exemple)
│
├── 📁 .gitlab/                       # CONFIGURATION GITLAB
│   ├── 📁 issue_templates/
│   │   ├── 📄 bug.md                # Template pour rapporter un bug
│   │   └── 📄 feature.md            # Template pour une nouvelle fonctionnalité
│   │
│   └── 📁 merge_request_templates/
│       └── 📄 default.md            # Template pour les Merge Requests
│
├── 📁 database/                      # BASE DE DONNÉES
│   ├── 📄 schema.sql                # SCHÉMA SQL COMPLET (le plus important!)
│   │   # Contient: users, alerts, threat_intelligence, network_assets, etc.
│   │   # 8 tables principales + fonctions + triggers + données initiales
│   │
│   ├── 📁 migrations/               # Migrations incrémentielles
│   │   ├── 📄 001_initial_schema.sql # Migration initiale
│   │   ├── 📄 002_add_ml_tables.sql  # Tables ML
│   │   └── 📄 003_add_response_tables.sql # Tables réponse
│   │
│   └── 📁 seeds/                    # Données initiales
│       ├── 📄 01_admin_user.sql     # Utilisateur admin par défaut
│       └── 📄 02_test_data.sql      # Données de test
│
├── 📁 docker/                        # CONFIGURATION DOCKER
│   ├── 📄 Dockerfile.web            # Image Flask + Python
│   ├── 📄 Dockerfile.zeek           # Image Zeek avec scripts custom
│   ├── 📄 Dockerfile.suricata       # Image Suricata pour signatures
│   ├── 📄 Dockerfile.postgres       # Image PostgreSQL optimisée
│   ├── 📄 Dockerfile.redis          # Image Redis
│   │
│   └── 📁 config/                   # Configurations spécifiques
│       ├── 📄 zeek-local.zeek       # Scripts Zeek personnalisés
│       ├── 📄 suricata.yaml         # Configuration Suricata
│       ├── 📄 nginx.conf            # Configuration Nginx (optionnel)
│       └── 📄 postgres-init.sh      # Script d'initialisation BD
│
├── 📁 src/                          # CODE SOURCE PRINCIPAL
│   │
│   ├── 📄 app.py                    # APPLICATION FLASK PRINCIPALE
│   │   # Point d'entrée, création de l'app, configuration, blueprints
│   │
│   ├── 📄 config.py                 # CONFIGURATION APPLICATION
│   │   # Charge .env, configuration Flask, chemins, constantes
│   │
│   ├── 📄 models.py                 # MODÈLES SQLALCHEMY (TOUS LES MODÈLES)
│   │   # User, Alert, ThreatIntelligence, NetworkAsset, ResponseAction, etc.
│   │   # Correspond exactement au schema.sql
│   │
│   ├── 📄 extensions.py             # EXTENSIONS FLASK
│   │   # SQLAlchemy, LoginManager, CSRFProtect, etc.
│   │
│   ├── 📁 core/                     # CŒUR DU SYSTÈME
│   │   ├── 📄 __init__.py
│   │   ├── 📄 event_bus.py         # Bus d'événements Redis (pub/sub)
│   │   ├── 📄 pipeline.py          # Pipeline de traitement temps réel
│   │   ├── 📄 priority_queue.py    # File prioritaire (TI ≥ 80 priorité absolue)
│   │   └── 📄 circuit_breaker.py   # Coupe-circuit (règle 5.1)
│   │
│   ├── 📁 ingestion/                # INGESTION DES DONNÉES
│   │   ├── 📄 __init__.py
│   │   ├── 📄 zeek_stream.py       # Lecture logs Zeek → Redis
│   │   ├── 📄 suricata_stream.py   # Lecture alertes Suricata → Redis
│   │   └── 📄 packet_capture.py    # Capture directe (backup avec Scapy)
│   │
│   ├── 📁 detection/                # DÉTECTION (UC14-UC19)
│   │   ├── 📄 __init__.py
│   │   ├── 📄 scoring.py           # Calcul score risque (5.2)
│   │   ├── 📄 signatures.py        # Moteur signatures (Suricata/Snort)
│   │   ├── 📄 ti_client.py         # Client Threat Intelligence (AbuseIPDB)
│   │   ├── 📄 correlation.py       # Corrélation événements
│   │   └── 📄 baselining.py        # Profilage UEBA
│   │
│   ├── 📁 ml/                       # MACHINE LEARNING (2.2.2)
│   │   ├── 📄 __init__.py
│   │   ├── 📄 trainer.py           # Entraînement modèles Scikit-learn
│   │   ├── 📄 predictor.py         # Prédictions en temps réel
│   │   ├── 📄 features.py          # Extraction des features
│   │   ├── 📄 feedback.py          # Feedback analyste → ML
│   │   └── 📄 model_registry.py    # Gestion versioning modèles
│   │
│   ├── 📁 response/                 # RÉPONSE ACTIVE (UC20-UC24)
│   │   ├── 📄 __init__.py
│   │   ├── 📄 decision_engine.py   # Moteur décision (5.3)
│   │   ├── 📄 firewall.py          # Gestion iptables/nftables
│   │   ├── 📄 honeypot.py          # Intégration honeypot (Cowrie)
│   │   ├── 📄 tarpit.py            # Implémentation tarpitting
│   │   ├── 📄 whitelist.py         # Liste blanche (IP admin)
│   │   └── 📄 fail_safe.py         # Mode sécurité par défaut
│   │
│   ├── 📁 resilience/               # RÉSILIENCE (UC25-UC29)
│   │   ├── 📄 __init__.py
│   │   ├── 📄 survival_mode.py     # Mode survie (5.4)
│   │   ├── 📄 critical_assets.py   # Gestion actifs vitaux
│   │   ├── 📄 qos_manager.py       # Priorisation CPU/RAM
│   │   └── 📄 microsegmentation.py # Micro-segmentation réseau
│   │
│   ├── 📁 auth/                     # AUTHENTIFICATION (UC01-UC13)
│   │   ├── 📄 __init__.py
│   │   ├── 📄 routes.py            # Routes Flask (login, register, etc.)
│   │   ├── 📄 rbac.py              # RBAC (5.5) - gestion permissions
│   │   ├── 📄 decorators.py        # Décorateurs pour contrôles d'accès
│   │   └── 📄 audit_logger.py      # Journalisation audit immuable
│   │
│   ├── 📁 api/                      # API REST
│   │   ├── 📄 __init__.py
│   │   └── 📁 v1/                  # Version 1 de l'API
│   │       ├── 📄 __init__.py
│   │       ├── 📄 alerts.py        # Endpoints alertes
│   │       ├── 📄 network.py       # Endpoints réseau
│   │       ├── 📄 response.py      # Endpoints réponse
│   │       └── 📄 system.py        # Endpoints système
│   │
│   ├── 📁 templates/                # TEMPLATES HTML (JINJA2)
│   │   ├── 📁 layouts/             # Layouts de base
│   │   │   ├── 📄 base.html        # Layout principal avec sidebar
│   │   │   └── 📄 auth_base.html   # Layout pages auth (sans sidebar)
│   │   │
│   │   ├── 📁 auth/                # AUTHENTIFICATION (UC01-UC13)
│   │   │   ├── 📄 login.html       # UC04 - Connexion
│   │   │   ├── 📄 setup.html       # UC01 - Setup initial
│   │   │   └── 📄 reset.html       # UC05 - Réinitialisation MDP
│   │   │
│   │   ├── 📁 dashboard/           # DASHBOARD SOC (5.2.1)
│   │   │   └── 📄 index.html       # Vue principale SOC
│   │   │
│   │   ├── 📁 alerts/              # CENTRE D'ALERTES (5.2.3)
│   │   │   ├── 📄 list.html        # UC15 - Liste alertes
│   │   │   └── 📄 detail.html      # Détail alerte
│   │   │
│   │   ├── 📁 network/             # TOPOLOGIE RÉSEAU (5.2.2)
│   │   │   └── 📄 topology.html    # Carte réseau interactive
│   │   │
│   │   ├── 📁 response/            # CONSOLE RIPOSTE (5.2.5)
│   │   │   └── 📄 console.html     # UC20-24 - Console actions
│   │   │
│   │   ├── 📁 admin/               # ADMINISTRATION (UC07-UC09)
│   │   │   ├── 📄 users.html       # UC07 - Gestion utilisateurs
│   │   │   └── 📄 config.html      # UC16-17 - Configuration
│   │   │
│   │   ├── 📁 resilience/          # CONTINUITÉ (5.2.6)
│   │   │   └── 📄 continuity.html  # UC25-29 - Gestion résilience
│   │   │
│   │   └── 📁 profile/             # PROFIL (UC10-UC13)
│   │       └── 📄 settings.html    # Paramètres utilisateur
│   │
│   └── 📁 static/                   # FICHIERS STATIQUES
│       ├── 📁 css/                  # Styles CSS
│       │   ├── 📄 main.css         # Styles principaux
│       │   └── 📄 critical.css     # Styles mode dégradé
│       │
│       └── 📁 js/                   # JavaScript
│           ├── 📄 main.js          # JS principal
│           ├── 📄 websocket.js     # Communication WebSocket temps réel
│           └── 📄 priority.js      # Gestion priorité UI
│
├── 📁 data/                         # DONNÉES PERSISTANTES
│   ├── 📁 zeek_logs/               # Logs Zeek (volume Docker)
│   ├── 📁 suricata_logs/           # Logs Suricata
│   ├── 📁 pgdata/                  # Données PostgreSQL
│   ├── 📁 ml_models/               # Modèles ML entraînés
│   ├── 📁 immutable_logs/          # Logs immuables (append-only)
│   └── 📁 backups/                 # Sauvegardes
│
├── 📁 scripts/                      # SCRIPTS UTILITAIRES
│   ├── 📄 setup.sh                 # Installation initiale
│   ├── 📄 backup.sh                # Sauvegarde complète
│   ├── 📄 restore.sh               # Restauration
│   ├── 📄 healthcheck.sh           # Vérification santé services
│   ├── 📄 update_signatures.sh     # Màj signatures Suricata
│   ├── 📄 test-database.sh         # Test connexion BD
│   │
│   └── 📁 attack_simulations/      # SIMULATIONS POUR TESTS
│       ├── 📄 port_scan.py         # Simulation scan ports
│       └── 📄 brute_force.py       # Simulation brute force
│
├── 📁 tests/                        # TESTS AUTOMATISÉS
│   ├── 📁 unit/                    # Tests unitaires
│   │   ├── 📄 test_auth.py         # Tests authentification
│   │   ├── 📄 test_detection.py    # Tests détection
│   │   ├── 📄 test_scoring.py      # Tests calcul score
│   │   └── 📄 test_response.py     # Tests réponse
│   │
│   ├── 📁 integration/             # Tests d'intégration
│   │   ├── 📄 test_docker.py       # Tests services Docker
│   │   └── 📄 test_api.py          # Tests API
│   │
│   └── 📁 pcaps/                   # CAPTURES RÉSEAU POUR TESTS
│       ├── 📄 port_scan.pcap       # Capture scan ports
│       └── 📄 brute_force.pcap     # Capture brute force
│
└── 📁 docs/                         # DOCUMENTATION
    ├── 📄 architecture.md          # Architecture technique
    ├── 📄 deployment.md            # Guide déploiement
    └── 📄 api.md                   # Documentation API