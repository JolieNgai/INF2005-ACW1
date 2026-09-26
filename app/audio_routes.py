"""Audio endpoints alongside main's home/image workflow and persistent keys."""
import base64
import io

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, jsonify, render_template, request, send_file

from . import audio_stego
from . import routes as main_routes

bp = Blueprint('audio', __name__, url_prefix='/audio')


@bp.get('')
def index():
    return render_template('audio.html')


@bp.post('/<action>')
def process(action):
    try:
        upload = request.files.get('audio')
        if upload is None or not upload.filename:
            raise ValueError('Choose a WAV file.')
        data = upload.read()
        if action == 'tamper':
            return send_file(io.BytesIO(audio_stego.tamper(data)), mimetype='audio/wav',
                             as_attachment=True, download_name='tampered.wav')
        bits = int(request.form.get('bits', '1'))
        start = int(request.form.get('start', '0'))
        if action == 'corrupt-payload':
            damaged = audio_stego.corrupt_payload(data, bits, start)
            return send_file(io.BytesIO(damaged), mimetype='audio/wav',
                             as_attachment=True, download_name='cannot_verify.wav')
        if action == 'capacity':
            return jsonify(capacity_bytes=audio_stego.capacity(data, bits, start))
        if action == 'embed':
            stego, info = audio_stego.embed(
                data, request.form.get('message', ''), main_routes.PRIVATE_KEY,
                bits, start, media_id=upload.filename)
            pem = main_routes.PUBLIC_KEY.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            return jsonify(**info, audio=base64.b64encode(stego).decode(),
                           public_key=pem.decode())
        if action == 'extract':
            # Default to main's persistent trusted key, just like image verification.
            # An explicit trusted key also allows another instance/demo to be verified.
            key_file = request.files.get('public_key')
            public = main_routes.PUBLIC_KEY
            if key_file is not None and key_file.filename:
                public = serialization.load_pem_public_key(key_file.read())
            if not isinstance(public, rsa.RSAPublicKey):
                raise ValueError('Use an RSA public key.')
            return jsonify(audio_stego.extract(data, public, bits, start))
        return jsonify(error='Unknown audio action.'), 404
    except UnsupportedAlgorithm:
        return jsonify(error='Unsupported public key. Use an RSA PEM public key.'), 400
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400


@bp.post('/generate-cannot-verify-test')
def generate_cannot_verify_test():
    from .audio_demo import demo_cover
    stego, _ = audio_stego.embed(demo_cover(), 'Cannot Verify demonstration',
                                main_routes.PRIVATE_KEY, bits=1, start=100)
    damaged = audio_stego.corrupt_payload(stego, bits=1, start=100)
    return send_file(io.BytesIO(damaged), mimetype='audio/wav',
                     as_attachment=True, download_name='cannot_verify.wav')
