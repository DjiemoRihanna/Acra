"""
ACRA - API REST
Endpoints pour l'interface et l'intégration externe
"""
from flask import Blueprint

api_bp = Blueprint('api', __name__)

from . import alerts, network, response, system

__all__ = [
    'api_bp',
    'alerts',
    'network',
    'response',
    'system'
]