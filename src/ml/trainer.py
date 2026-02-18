"""
Module ML - Entraînement des modèles Scikit-learn pour ACRA SOC
"""
import os
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import logging
import threading
import time

from src.extensions import db
from src.models import NetworkFlow, Alert
from src.core.event_bus import bus

class MLTrainer:
    """
    Entraînement des modèles de Machine Learning
    Utilise Scikit-learn pour la détection d'anomalies
    """
    
    def __init__(self, app=None):
        self.app = app
        self.running = True
        self.thread = None
        self.models_path = "/app/data/ml_models/"
        os.makedirs(self.models_path, exist_ok=True)
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.retrain_interval = int(os.getenv('ML_RETRAIN_INTERVAL', 3600))  # 1 heure
        self.min_samples = 1000  # Minimum d'échantillons pour entraîner
        
        self.logger.info("🧠 Initialisation du module ML Trainer")
    
    def start(self):
        """Démarre le thread d'entraînement"""
        if self.thread is None or not self.thread.is_alive():
            self.running = True
            self.thread = threading.Thread(target=self._training_loop, daemon=True)
            self.thread.start()
            self.logger.info("✅ ML Trainer démarré")
    
    def stop(self):
        """Arrête le thread d'entraînement"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.logger.info("🛑 ML Trainer arrêté")
    
    def _training_loop(self):
        """Boucle principale d'entraînement"""
        while self.running:
            try:
                self.logger.info("🔄 Démarrage de l'entraînement ML...")
                
                with self.app.app_context():
                    # Extraire les features
                    X, y = self._extract_training_data()
                    
                    if len(X) >= self.min_samples:
                        # Entraîner le modèle Isolation Forest (non supervisé)
                        self._train_isolation_forest(X)
                        
                        # Entraîner le modèle supervisé si on a des labels
                        if y is not None and len(y) > 100:
                            self._train_classifier(X, y)
                        
                        self.logger.info("✅ Entraînement ML terminé")
                    else:
                        self.logger.info(f"⏳ Pas assez de données: {len(X)} < {self.min_samples}")
                
                # Attendre avant le prochain entraînement
                for _ in range(self.retrain_interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"❌ Erreur entraînement ML: {e}")
                time.sleep(300)
    
    def _extract_training_data(self):
        """
        Extrait les données d'entraînement depuis les flux réseau
        """
        # Période d'entraînement: 30 derniers jours
        end = datetime.utcnow()
        start = end - timedelta(days=30)
        
        # Récupérer les flux
        flows = NetworkFlow.query.filter(
            NetworkFlow.ts.between(start, end)
        ).limit(10000).all()
        
        if len(flows) < 100:
            return [], None
        
        # Extraire les features
        features = []
        labels = []
        
        for flow in flows:
            feature_vector = self._extract_features(flow)
            features.append(feature_vector)
            
            # Vérifier si ce flux a généré une alerte
            alert = Alert.query.filter_by(flow_id=flow.id).first()
            labels.append(1 if alert else 0)
        
        return np.array(features), np.array(labels)
    
    def _extract_features(self, flow):
        """
        Extrait les features d'un flux pour le ML
        """
        return [
            flow.orig_bytes or 0,
            flow.resp_bytes or 0,
            flow.duration or 0,
            flow.source_port or 0,
            flow.dest_port or 0,
            1 if flow.source_is_internal else 0,
            1 if flow.dest_is_internal else 0,
            hash(flow.protocol or '') % 100,  # Encodage simple du protocole
            flow.ts.hour,  # Heure de la journée
            flow.ts.weekday(),  # Jour de la semaine
        ]
    
    def _train_isolation_forest(self, X):
        """
        Entraîne un modèle Isolation Forest (détection d'anomalies non supervisée)
        """
        self.logger.info("🌲 Entraînement Isolation Forest...")
        
        # Normalisation
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Modèle
        model = IsolationForest(
            contamination=0.1,  # 10% d'anomalies
            random_state=42,
            n_estimators=100
        )
        
        model.fit(X_scaled)
        
        # Sauvegarde
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        joblib.dump(scaler, f"{self.models_path}/scaler_if_{timestamp}.joblib")
        joblib.dump(model, f"{self.models_path}/isolation_forest_{timestamp}.joblib")
        
        # Garder une copie comme modèle courant
        joblib.dump(scaler, f"{self.models_path}/scaler_if_latest.joblib")
        joblib.dump(model, f"{self.models_path}/isolation_forest_latest.joblib")
        
        # Publier l'événement
        bus.publish('ml:model_updated', {
            'model_type': 'isolation_forest',
            'timestamp': timestamp,
            'samples': len(X)
        })
        
        self.logger.info(f"💾 Modèle Isolation Forest sauvegardé ({len(X)} échantillons)")
    
    def _train_classifier(self, X, y):
        """
        Entraîne un classifieur supervisé (Random Forest)
        """
        self.logger.info("🌲 Entraînement Random Forest Classifier...")
        
        # Normalisation
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        # Modèle
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        model.fit(X_train, y_train)
        
        # Évaluation
        score = model.score(X_test, y_test)
        self.logger.info(f"📊 Précision du modèle: {score:.2f}")
        
        # Sauvegarde
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        joblib.dump(scaler, f"{self.models_path}/scaler_rf_{timestamp}.joblib")
        joblib.dump(model, f"{self.models_path}/random_forest_{timestamp}.joblib")
        
        # Garder une copie comme modèle courant
        joblib.dump(scaler, f"{self.models_path}/scaler_rf_latest.joblib")
        joblib.dump(model, f"{self.models_path}/random_forest_latest.joblib")
        
        # Publier l'événement
        bus.publish('ml:model_updated', {
            'model_type': 'random_forest',
            'timestamp': timestamp,
            'accuracy': score,
            'samples': len(X)
        })

# Instance singleton
trainer = None

def init_trainer(app):
    global trainer
    trainer = MLTrainer(app)
    trainer.start()
    return trainer

def get_trainer():
    return trainer