"""
Module ML - Gestion du versioning des modèles
"""
import os
import json
import joblib
from datetime import datetime
import logging

from src.core.event_bus import bus

class ModelRegistry:
    """
    Registre des modèles ML avec versioning
    """
    
    def __init__(self, app=None):
        self.app = app
        self.models_path = "/app/data/ml_models/"
        self.registry_file = f"{self.models_path}/model_registry.json"
        self.registry = self._load_registry()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("📚 Model Registry initialisé")
    
    def _load_registry(self):
        """Charge le registre depuis le fichier JSON"""
        if os.path.exists(self.registry_file):
            try:
                with open(self.registry_file, 'r') as f:
                    return json.load(f)
            except:
                return {'models': {}, 'latest': {}}
        return {'models': {}, 'latest': {}}
    
    def _save_registry(self):
        """Sauvegarde le registre dans le fichier JSON"""
        with open(self.registry_file, 'w') as f:
            json.dump(self.registry, f, indent=2)
    
    def register_model(self, model_type, version, metrics=None):
        """
        Enregistre un nouveau modèle
        """
        if model_type not in self.registry['models']:
            self.registry['models'][model_type] = []
        
        model_info = {
            'version': version,
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics or {},
            'path': f"{self.models_path}/{model_type}_{version}.joblib"
        }
        
        self.registry['models'][model_type].append(model_info)
        self.registry['latest'][model_type] = version
        
        self._save_registry()
        
        self.logger.info(f"✅ Modèle {model_type} v{version} enregistré")
        
        # Publier l'événement
        bus.publish('ml:model_registered', {
            'model_type': model_type,
            'version': version,
            'metrics': metrics
        })
    
    def get_latest_version(self, model_type):
        """
        Retourne la dernière version d'un modèle
        """
        return self.registry['latest'].get(model_type)
    
    def get_model_info(self, model_type, version=None):
        """
        Retourne les informations d'un modèle
        """
        if model_type not in self.registry['models']:
            return None
        
        if version is None:
            version = self.get_latest_version(model_type)
        
        for model in self.registry['models'][model_type]:
            if model['version'] == version:
                return model
        
        return None
    
    def list_models(self, model_type=None):
        """
        Liste tous les modèles ou ceux d'un type spécifique
        """
        if model_type:
            return self.registry['models'].get(model_type, [])
        return self.registry['models']
    
    def delete_model(self, model_type, version):
        """
        Supprime un modèle (admin only)
        """
        if model_type not in self.registry['models']:
            return False
        
        models = self.registry['models'][model_type]
        self.registry['models'][model_type] = [
            m for m in models if m['version'] != version
        ]
        
        # Mettre à jour le latest si nécessaire
        if self.registry['latest'].get(model_type) == version:
            if self.registry['models'][model_type]:
                self.registry['latest'][model_type] = self.registry['models'][model_type][-1]['version']
            else:
                del self.registry['latest'][model_type]
        
        self._save_registry()
        
        # Supprimer le fichier
        model_path = f"{self.models_path}/{model_type}_{version}.joblib"
        if os.path.exists(model_path):
            os.remove(model_path)
        
        self.logger.info(f"🗑️ Modèle {model_type} v{version} supprimé")
        return True
    
    def get_stats(self):
        """
        Retourne les statistiques du registre
        """
        return {
            'total_models': sum(len(m) for m in self.registry['models'].values()),
            'model_types': list(self.registry['models'].keys()),
            'latest_versions': self.registry['latest']
        }


# Instance singleton
registry = None

def init_registry(app):
    global registry
    registry = ModelRegistry(app)
    return registry

def get_registry():
    return registry