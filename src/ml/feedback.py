"""
Module ML - Feedback des analystes pour améliorer les modèles
"""
import logging
import numpy as np
from datetime import datetime

from src.extensions import db
from src.models import Alert
from src.core.event_bus import bus

class MLFeedback:
    """
    Gestion du feedback des analystes pour améliorer les modèles
    """
    
    def __init__(self, app=None):
        self.app = app
        self.feedback_buffer = []
        self.buffer_size = 100
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # S'abonner aux événements de feedback
        bus.subscribe('analyst_feedback', self.handle_feedback)
        
        self.logger.info("📝 ML Feedback initialisé")
    
    def handle_feedback(self, data):
        """
        Traite le feedback d'un analyste
        """
        alert_id = data.get('alert_id')
        is_true_positive = data.get('is_true_positive')
        scores = data.get('scores', {})
        
        self.logger.info(f"Feedback reçu pour alerte {alert_id}: {'TP' if is_true_positive else 'FP'}")
        
        # Stocker pour ré-entraînement
        self.feedback_buffer.append({
            'alert_id': alert_id,
            'is_true_positive': is_true_positive,
            'scores': scores,
            'timestamp': datetime.now()
        })
        
        # Si le buffer est plein, déclencher un ré-entraînement
        if len(self.feedback_buffer) >= self.buffer_size:
            self.trigger_retraining()
    
    def trigger_retraining(self):
        """
        Déclenche un ré-entraînement basé sur le feedback
        """
        self.logger.info("🔄 Déclenchement du ré-entraînement basé sur le feedback")
        
        # Analyser le feedback
        tp_count = sum(1 for f in self.feedback_buffer if f['is_true_positive'])
        fp_count = len(self.feedback_buffer) - tp_count
        
        accuracy = tp_count / len(self.feedback_buffer) if self.feedback_buffer else 0
        
        self.logger.info(f"📊 Feedback: {tp_count} TP, {fp_count} FP, accuracy: {accuracy:.2f}")
        
        # Publier un événement pour le ré-entraînement
        bus.publish('ml:retrain_requested', {
            'reason': 'feedback_buffer_full',
            'samples': len(self.feedback_buffer),
            'accuracy': accuracy,
            'timestamp': datetime.now().isoformat()
        })
        
        # Vider le buffer
        self.feedback_buffer = []
    
    def get_feedback_stats(self):
        """
        Retourne les statistiques de feedback
        """
        return {
            'buffer_size': len(self.feedback_buffer),
            'buffer_capacity': self.buffer_size
        }


# Instance singleton
feedback = None

def init_feedback(app):
    global feedback
    feedback = MLFeedback(app)
    return feedback

def get_feedback():
    return feedback