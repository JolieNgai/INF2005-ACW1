from flask import Flask, jsonify, request, render_template

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

    from .verdict import verdict_from_exception

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        verdict, explanation = verdict_from_exception(e)
        if request.path.startswith('/audio'):
            return jsonify(error=explanation, verdict=verdict.value), 500
        return render_template('home.html', error=explanation, verdict=verdict.value), 500

    return app