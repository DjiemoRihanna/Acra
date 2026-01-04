# Utilisation de l'image officielle maintenue par l'équipe Zeek
FROM zeek/zeek:latest

# Création du dossier pour les logs
WORKDIR /usr/local/zeek/logs

# Installation de curl pour pouvoir tester la connectivité
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Commande de lancement
# -i eth0 : écoute sur l'interface par défaut de Docker
# local : charge les scripts de base de Zeek
CMD ["zeek", "-i", "eth0", "local"]