"""
Alert management API endpoints
Will handle alert listing, details, and management
"""
from flask import Blueprint

alerts_bp = Blueprint('alerts', __name__)

# Routes will be added later when we refactor alert-related functionality