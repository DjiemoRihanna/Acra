def init_app(app):
    """Initialize all API blueprints with Flask app"""
    # Import ici pour éviter les imports circulaires
    from .alerts import alerts_bp
    from .network import network_bp
    from .system import system_bp
    from .response import response_bp
    
    # Enregistrement des API REST (Elles renvoient du JSON)
    app.register_blueprint(alerts_bp, url_prefix='/api/v1/alerts')
    app.register_blueprint(network_bp, url_prefix='/api/v1/network')
    app.register_blueprint(system_bp, url_prefix='/api/v1/system')
    app.register_blueprint(response_bp, url_prefix='/api/v1/response')
    
    
    print("[API] REST API package initialized")