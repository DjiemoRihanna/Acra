import logging
from src.core.constants import CRITICAL_PRIORITY_THRESHOLD, CRITICAL_TI_THRESHOLD, SCORE_MULTIPLIER_DEFAULT

# Configuration du logger
logger = logging.getLogger(__name__)

def evaluate_and_block(ip, ti_score, priority):
    """Évalue la dangerosité et décide du blocage."""
    
    if priority <= CRITICAL_PRIORITY_THRESHOLD or ti_score >= CRITICAL_TI_THRESHOLD:
        logger.warning(f"COUPE-CIRCUIT : Menace critique identifiée pour l'IP {ip} (Score TI: {ti_score}, Priorité: {priority})")
        return 100.0
    
    return float(ti_score * SCORE_MULTIPLIER_DEFAULT)