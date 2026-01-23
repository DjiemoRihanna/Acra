# Utilisation de l'image officielle Zeek (Debian-based)
FROM zeek/zeek:latest

# Installation des outils réseau nécessaires (iproute2) pour la détection d'interfaces
RUN apt-get update && apt-get install -y \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Création du dossier pour les logs
WORKDIR /usr/local/zeek/logs

# --- AUTOMATISATION DU SCRIPT D'ENTRÉE ---

# Copie le script de l'hôte vers l'image
COPY docker/zeek_entrypoint.sh /zeek_entrypoint.sh

# Rendre le script exécutable automatiquement
RUN chmod +x /zeek_entrypoint.sh

# Nettoyage automatique des retours à la ligne (au cas où le fichier vienne de Windows)
RUN sed -i 's/\r$//' /zeek_entrypoint.sh

# On reste en root pour permettre la capture de paquets sur les interfaces physiques
USER root

# Pas de CMD ici, elle sera définie dans le docker-compose