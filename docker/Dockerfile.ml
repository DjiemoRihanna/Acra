# Image ML pour ACRA SOC (Scikit-learn)
FROM python:3.11-slim

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copie des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Dépendances ML supplémentaires
RUN pip install --no-cache-dir \
    scikit-learn==1.3.0 \
    numpy==1.24.3 \
    pandas==2.0.3 \
    joblib==1.3.2

# Copie du code source
COPY . .

# Création du répertoire pour les modèles
RUN mkdir -p /app/data/ml_models

# Script d'entrée
COPY docker/ml-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]