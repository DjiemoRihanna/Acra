"""
Module de coupe-circuit pour ACRA SOC (règle 5.1)
"""
import logging
from src.core.event_bus import bus

class CircuitBreaker:
    """
    Implémentation du coupe-circuit :
    - TI ≥ 80 → score forcé à 100
    - Signature priorité 10 → score forcé à 100
    """
    
    def __init__(self, app=None):
        self.app = app
        self.ti_threshold = 80
        self.signature_priority = 10
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def check_ti(self, ti_score):
        """Vérifie si le score TI déclenche le coupe-circuit"""
        if ti_score >= self.ti_threshold:
            self.logger.warning(f"⚡ COUPE-CIRCUIT: TI={ti_score} ≥ {self.ti_threshold}")
            bus.publish('circuit_breaker', {
                'type': 'ti',
                'value': ti_score,
                'threshold': self.ti_threshold
            })
            return True
        return False
    
    def check_signature(self, priority):
        """Vérifie si la priorité de signature déclenche le coupe-circuit"""
        if priority >= self.signature_priority:
            self.logger.warning(f"⚡ COUPE-CIRCUIT: Signature priorité={priority} ≥ {self.signature_priority}")
            bus.publish('circuit_breaker', {
                'type': 'signature',
                'value': priority,
                'threshold': self.signature_priority
            })
            return True
        return False