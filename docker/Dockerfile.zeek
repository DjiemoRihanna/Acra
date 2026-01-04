FROM debian:bookworm-slim

# Installation de Zeek et des dépendances
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    ca-certificates \
    libpcap0.8 \
    python3 \
    && echo 'deb http://download.opensuse.org/repositories/network:/zeek/Debian_12/ /' | tee /etc/apt/sources.list.d/network:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/network:/zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/network_zeek.gpg > /dev/null \
    && apt-get update && apt-get install -y zeek-lts

# Configuration du PATH
ENV PATH="/opt/zeek/bin:${PATH}"

# Création du dossier de logs
RUN mkdir -p /usr/local/zeek/logs

# Copie de ta config personnalisée (Méthode Hybride)
COPY docker/config/zeek-local.zeek /opt/zeek/share/zeek/site/local.zeek

WORKDIR /usr/local/zeek/logs

# Lancement de Zeek sur l'interface par défaut (souvent eth0 en docker, sera surchargé par network_mode: host)
CMD ["zeek", "-i", "eth0", "local", "Log::default_rotation_interval=1min"]