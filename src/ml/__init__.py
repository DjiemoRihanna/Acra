"""
Module Machine Learning pour ACRA SOC
Entraînement, prédiction et feedback pour l'analyse comportementale
"""

from .trainer import MLTrainer, init_trainer, get_trainer
from .predictor import MLPredictor, init_predictor, get_predictor
from .features import FeatureExtractor
from .feedback import MLFeedback, init_feedback, get_feedback
from .model_registry import ModelRegistry, init_registry, get_registry

__all__ = [
    'MLTrainer',
    'init_trainer',
    'get_trainer',
    'MLPredictor',
    'init_predictor',
    'get_predictor',
    'FeatureExtractor',
    'MLFeedback',
    'init_feedback',
    'get_feedback',
    'ModelRegistry',
    'init_registry',
    'get_registry'
]


def init_ml(app):
    """
    Initialise tous les composants ML
    """
    print("[ML] 🧠 Initialisation des composants Machine Learning...")
    
    # Initialiser dans l'ordre
    registry = init_registry(app)
    trainer = init_trainer(app)
    predictor = init_predictor(app)
    feedback = init_feedback(app)
    
    print("[ML] ✅ Composants ML initialisés")
    
    return {
        'trainer': trainer,
        'predictor': predictor,
        'feedback': feedback,
        'registry': registry
    }


def get_ml_stats():
    """
    Récupère les statistiques de tous les composants ML
    """
    stats = {
        'trainer': {},
        'predictor': {},
        'feedback': {},
        'registry': {}
    }
    
    try:
        t = get_trainer()
        if t:
            stats['trainer'] = {'status': 'active'}
    except:
        pass
    
    try:
        p = get_predictor()
        if p:
            stats['predictor'] = {
                'models_loaded': {
                    'isolation_forest': p.isolation_forest is not None,
                    'random_forest': p.random_forest is not None
                }
            }
    except:
        pass
    
    try:
        f = get_feedback()
        if f:
            stats['feedback'] = f.get_feedback_stats()
    except:
        pass
    
    try:
        r = get_registry()
        if r:
            stats['registry'] = r.get_stats()
    except:
        pass
    
    return stats