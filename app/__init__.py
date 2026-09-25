from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
    @app.errorhandler(413)
    def too_large(error):
        return {'error': 'Upload exceeds the 20 MiB request limit.'}, 413
    from .routes import bp
    app.register_blueprint(bp)
    from .audio_routes import bp as audio_bp
    app.register_blueprint(audio_bp)
    from .attack_routes import bp as attack_bp
    app.register_blueprint(attack_bp)
    return app
