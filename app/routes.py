import os
import json
from flask import Blueprint, request, render_template, send_from_directory
from PIL import Image
from dotenv import load_dotenv

from .crypto_payload import (
    generate_keypair, stable_hash, build_payload,
    sign_payload, run_verification
)
from .image_stego import check_capacity, embed_payload, extract_payload

from .verdict import Verdict, verdict_from_exception

load_dotenv()

bp = Blueprint('main', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # .../app
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')       # .../app/uploads
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============================================================
# Persistent RSA keys
# ============================================================

KEY_FOLDER = os.path.join(BASE_DIR, 'keys')
PRIVATE_KEY_PATH = os.path.join(KEY_FOLDER, 'private_key.pem')
PUBLIC_KEY_PATH = os.path.join(KEY_FOLDER, 'public_key.pem')

os.makedirs(KEY_FOLDER, exist_ok=True)


def load_or_create_keys():
    """Load existing RSA keys, or create them on first startup."""

    from cryptography.hazmat.primitives import serialization

    # If keys already exist, load them
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):

        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )

        return private_key, public_key

    # Otherwise, generate a new keypair
    private_key, public_key = generate_keypair()

    # Save private key
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key, public_key


PRIVATE_KEY, PUBLIC_KEY = load_or_create_keys()

# Secret key used for start-location derivation in env file

SECRET_KEY_PHRASE = os.getenv("STEGO_SECRET_KEY")

if not SECRET_KEY_PHRASE:
    raise RuntimeError(
        "STEGO_SECRET_KEY is not configured. "
        "Please create a .env file with STEGO_SECRET_KEY=..."
    )


def pack_payload(payload: dict, signature: bytes) -> bytes:
    package = {"payload": payload, "signature": signature.hex()}
    return json.dumps(package, sort_keys=True).encode()


def unpack_payload(data: bytes) -> tuple[dict, bytes]:
    package = json.loads(data.decode())
    return package["payload"], bytes.fromhex(package["signature"])


@bp.route('/')
def index():
    return render_template('home.html')


@bp.route('/image')
def image_stego_page():
    return render_template('image_stego.html')


@bp.route('/uploads/<filename>')
def get_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@bp.route('/embed', methods=['POST'])
def embed():
    file = request.files.get('cover_image')

    try:
        bits = int(request.form.get('bits_per_channel', 1))
    except (TypeError, ValueError):
        return "Invalid bits per channel value", 400

    if bits < 1 or bits > 8:
        return "Bits per channel must be between 1 and 8", 400

    if not file or file.filename == '':
        return "No file selected", 400

    if not file.filename.lower().endswith('.png'):
        return "Only PNG files are supported", 400

    cover_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(cover_path)

    try:
        img = Image.open(cover_path)
        img.verify()

        # Re-open after verify()
        img = Image.open(cover_path).convert("RGB")

    except Exception:
        return render_template(
            'image_stego.html',
            error="Invalid or corrupted PNG image",
            bits=bits,
        ), 400

    width, height = img.size

    # Hash a "stable representation" — bottom N bits masked off —
    # so that embedding itself doesn't break verification later.
    cover_hash = stable_hash(img.tobytes(), bits)

    payload = build_payload(
        media_id=file.filename,
        cover_hash=cover_hash,
        metadata={
            "team": "P6-7",
            "bits_per_channel": bits
        },
    )

    signature = sign_payload(PRIVATE_KEY, payload)
    data_to_embed = pack_payload(payload, signature)

    fits, msg = check_capacity(
        width,
        height,
        3,
        len(data_to_embed),
        bits
    )

    if not fits:
        return f"Capacity error: {msg}", 400

    stego_filename = f"stego_{file.filename}"
    stego_path = os.path.join(UPLOAD_FOLDER, stego_filename)

    embed_payload(
        cover_path,
        stego_path,
        data_to_embed,
        SECRET_KEY_PHRASE,
        bits_per_channel=bits
    )

    return render_template(
        'image_stego.html',
        cover_filename=file.filename,
        stego_filename=stego_filename,
        bits=bits,
        capacity_msg=msg,
    )


@bp.route('/verify', methods=['POST'])
def verify():
    file = request.files.get('stego_image')
    
    try:
        bits = int(request.form.get('bits_per_channel', 1))
    except (TypeError, ValueError):
        return "Invalid bits per channel value", 400

    if bits < 1 or bits > 8:
        return "Bits per channel must be between 1 and 8", 400

    if not file or file.filename == '':
        return "No file selected", 400
    
    if not file.filename.lower().endswith('.png'):
        return "Only PNG files are supported", 400

    # Save under its own name so this is a genuinely independent upload,
    # not just re-reading the file /embed already wrote.
    verify_path = os.path.join(UPLOAD_FOLDER, f"verify_{file.filename}")
    file.save(verify_path)

    # Validate that the uploaded file is a readable PNG.
    try:
        img = Image.open(verify_path)
        img.verify()
    except Exception:
        return render_template(
            'image_stego.html',
            error="Invalid or corrupted PNG image",
            bits=bits,
        ), 400

    verdict, payload = run_verification(
        stego_path=verify_path,
        key=SECRET_KEY_PHRASE,
        bits=bits,
        public_key=PUBLIC_KEY,
        unpack_payload_fn=unpack_payload,
        extract_payload_fn=extract_payload,
    )

    return render_template(
        'image_stego.html',
        verdict=verdict,
        extracted_payload=payload,
        bits=bits,
    )

@bp.errorhandler(Exception)
def handle_unexpected_error(e):
    verdict, explanation = verdict_from_exception(e)
    return render_template('home.html', error=explanation, verdict=verdict.value), 500