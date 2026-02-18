"""
Module de détection avancée pour ACRA SOC
Comprend le scoring, les signatures, la Threat Intelligence, la corrélation et l'UEBA
"""

from .ti_client import ThreatIntelligenceClient, init_ti_client, get_ti_client
from .signatures import SignatureEngine, init_signature_engine, get_signature_engine
from .scoring import ScoringEngine, init_scoring_engine, get_scoring_engine
from .correlation import CorrelationEngine, init_correlation_engine, get_correlation_engine
from .baselining import BaseliningEngine, init_baselining_engine, get_baselining_engine

# SUPPRIMEZ CETTE LIGNE :
# from .extensions import db, login_manager, csrf, migrate, redis_client

__all__ = [
    'ThreatIntelligenceClient',
    'init_ti_client',
    'get_ti_client',
    'SignatureEngine',
    'init_signature_engine',
    'get_signature_engine',
    'ScoringEngine',
    'init_scoring_engine',
    'get_scoring_engine',
    'CorrelationEngine',
    'init_correlation_engine',
    'get_correlation_engine',
    'BaseliningEngine',
    'init_baselining_engine',
    'get_baselining_engine',
]


def init_detection(app):
    """
    Initialise tous les moteurs de détection
    """
    print("[DETECTION] 🧠 Initialisation des moteurs de détection...")
    
    ti_client = init_ti_client(app)
    signature_engine = init_signature_engine(app)
    scoring_engine = init_scoring_engine(app)
    correlation_engine = init_correlation_engine(app)
    baselining_engine = init_baselining_engine(app)
    
    print("[DETECTION] ✅ Moteurs de détection initialisés")
    
    return {
        'ti_client': ti_client,
        'signature_engine': signature_engine,
        'scoring_engine': scoring_engine,
        'correlation_engine': correlation_engine,
        'baselining_engine': baselining_engine
    }