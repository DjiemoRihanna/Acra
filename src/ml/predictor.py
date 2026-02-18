"""
Module ML - Prédictions en temps réel pour ACRA SOC
"""
import os
import joblib
import numpy as np
from datetime import datetime
import logging

from src.core.event_bus import bus
from src.ml.features import FeatureExtractor

class MLPredictor:
    """
    Prédictions en temps réel avec les modèles ML entraînés
    """
    
    def __init__(self, app=None):
        self.app = app
        self.models_path = "/app/data/ml_models/"
        self.isolation_forest = None
        self.random_forest = None
        self.scaler_if = None
        self.scaler_rf = None
        self.feature_extractor = FeatureExtractor()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Charger les derniers modèles
        self._load_latest_models()
        
        self.logger.info("🔮 ML Predictor initialisé")
    
    def _load_latest_models(self):
        """Charge les derniers modèles entraînés"""
        try:
            # Isolation Forest
            if_path = f"{self.models_path}/isolation_forest_latest.joblib"
            scaler_if_path = f"{self.models_path}/scaler_if_latest.joblib"
            
            if os.path.exists(if_path) and os.path.exists(scaler_if_path):
                self.isolation_forest = joblib.load(if_path)
                self.scaler_if = joblib.load(scaler_if_path)
                self.logger.info("✅ Modèle Isolation Forest chargé")
            
            # Random Forest
            rf_path = f"{self.models_path}/random_forest_latest.joblib"
            scaler_rf_path = f"{self.models_path}/scaler_rf_latest.joblib"
            
            if os.path.exists(rf_path) and os.path.exists(scaler_rf_path):
                self.random_forest = joblib.load(rf_path)
                self.scaler_rf = joblib.load(scaler_rf_path)
                self.logger.info("✅ Modèle Random Forest chargé")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur chargement modèles: {e}")
    
    def predict_anomaly(self, flow_data):
        """
        Prédit si un flux est une anomalie (score 0-100)
        """
        if self.isolation_forest is None or self.scaler_if is None:
            return 0
        
        try:
            # Extraire les features
            features = self.feature_extractor.extract_from_flow(flow_data)
            
            # Normaliser
            features_scaled = self.scaler_if.transform([features])
            
            # Prédiction Isolation Forest
            # -1 = anomalie, 1 = normal
            pred = self.isolation_forest.predict(features_scaled)[0]
            
            # Score d'anomalie (convertir -1/1 en 0-100)
            if pred == -1:  # Anomalie
                # Score basé sur la distance à la frontière de décision
                score = self.isolation_forest.score_samples(features_scaled)[0]
                # Normaliser le score (plus il est négatif, plus c'est anormal)
                anomaly_score = min(100, max(0, -score * 10))
            else:
                anomaly_score = 0
            
            return int(anomaly_score)
            
        except Exception as e:
            self.logger.error(f"Erreur prédiction anomalie: {e}")
            return 0
    
    def predict_category(self, flow_data):
        """
        Prédit la catégorie de menace (si supervisé)
        """
        if self.random_forest is None or self.scaler_rf is None:
            return None
        
        try:
            features = self.feature_extractor.extract_from_flow(flow_data)
            features_scaled = self.scaler_rf.transform([features])
            
            # Prédiction de la classe
            pred_class = self.random_forest.predict(features_scaled)[0]
            
            # Probabilités
            proba = self.random_forest.predict_proba(features_scaled)[0]
            confidence = float(max(proba))
            
            return {
                'class': int(pred_class),
                'confidence': confidence,
                'probabilities': proba.tolist()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur prédiction catégorie: {e}")
            return None
    
    def get_anomaly_score(self, flow_data):
        """
        Retourne le score ML (0-100) pour le scoring engine
        """
        score = self.predict_anomaly(flow_data)
        
        # Publier l'événement
        bus.publish('ml:prediction', {
            'flow_id': flow_data.get('id'),
            'anomaly_score': score,
            'timestamp': datetime.now().isoformat()
        })
        
        return score


# Instance singleton
predictor = None

def init_predictor(app):
    global predictor
    predictor = MLPredictor(app)
    return predictor

def get_predictor():
    return predictor