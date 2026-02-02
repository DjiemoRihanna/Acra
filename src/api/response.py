"""
Active response API endpoints
Will handle firewall rules, honeypot management, and response actions
"""
from flask import Blueprint

response_bp = Blueprint('response', __name__)

# Routes will be added later when we refactor response-related functionality