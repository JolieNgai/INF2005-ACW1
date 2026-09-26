import os
import json
from flask import Blueprint, request, render_template, send_from_directory
from PIL import Image
from dotenv import load_dotenv
from .validation import validate_upload, validate_bits
from .verdict import Verdict, verdict_from_exception
from .crypto_payload import (
    generate_keypair, stable_hash, build_payload,
    sign_payload, run_verification
)
from .image_stego import check_capacity, embed_payload, extract_payload

load_dotenv()

bp = Blueprint('main', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # .../app
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')       # .../app/uploads
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Persistent RSA keys
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
    message = request.form.get('message', '').strip()

    ok, err = validate_upload(file, ('.png',))
    if not ok:
        return render_template('image_stego.html', error=err), 400

    bits, err = validate_bits(request.form.get('bits_per_channel'))
    if bits is None:
        return render_template('image_stego.html', error=err), 400

    if not message:
        return render_template(
            'image_stego.html',
            error="Please enter a message to hide",
            bits=bits,
        ), 400

    cover_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(cover_path)

    try:
        img = Image.open(cover_path)
        img.verify()
        img = Image.open(cover_path).convert("RGB")
    except Exception:
        return render_template('image_stego.html', error="Invalid or corrupted PNG image", bits=bits), 400

    width, height = img.size
    cover_hash = stable_hash(img.tobytes(), bits)
    payload = build_payload(
        media_id=file.filename,
        cover_hash=cover_hash,
        metadata={
            "team": "P6-7",
            "bits_per_channel": bits,
            "message": message,
        },
    )
    signature = sign_payload(PRIVATE_KEY, payload)
    data_to_embed = pack_payload(payload, signature)

    fits, msg = check_capacity(width, height, 3, len(data_to_embed), bits)
    if not fits:
        return render_template('image_stego.html', error=f"Capacity error: {msg}", bits=bits), 400

    stego_filename = f"stego_{file.filename}"
    stego_path = os.path.join(UPLOAD_FOLDER, stego_filename)
    embed_payload(cover_path, stego_path, data_to_embed, SECRET_KEY_PHRASE, bits_per_channel=bits)

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

    ok, err = validate_upload(file, ('.png',))
    if not ok:
        return render_template('image_stego.html', error=err), 400

    bits, err = validate_bits(request.form.get('bits_per_channel'))
    if bits is None:
        return render_template('image_stego.html', error=err), 400

    verify_path = os.path.join(UPLOAD_FOLDER, f"verify_{file.filename}")
    file.save(verify_path)

    try:
        img = Image.open(verify_path)
        img.verify()
    except Exception:
        return render_template('image_stego.html', error="Invalid or corrupted PNG image", bits=bits), 400

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
        verdict=verdict.value,   # .value gives the display string, e.g. "Authentic"
        extracted_payload=payload,
        bits=bits,
        verified_filename=file.filename,
    )


@bp.route('/generate-signature-invalid-test', methods=['POST'])
def generate_signature_invalid_test():
    """
    Demo/test utility: builds and signs a real payload normally, then flips
    one byte of the signature before packing and embedding it, using the
    exact same embed_payload() pipeline as a normal embed. The result is a
    well-formed JSON payload+signature package so it authenticates fine
    at the start-location/HMAC layer and parses fine as JSON but the
    signature itself no longer matches the payload, which is exactly what
    triggers the Signature Invalid verdict on /verify.
    """
    cover_path = os.path.join(UPLOAD_FOLDER, "_tmp_cover_for_sig_invalid.png")
    output_filename = "signature_invalid_test.png"
    output_path = os.path.join(UPLOAD_FOLDER, output_filename)

    dummy_cover = Image.new("RGB", (200, 200), color=(120, 130, 140))
    dummy_cover.save(cover_path, "PNG")

    test_bits = 1 #impt to use 1 bit in LSB when verifying

    payload = build_payload(
        media_id="signature_invalid_test.png",
        cover_hash=stable_hash(dummy_cover.convert("RGB").tobytes(), test_bits),
        metadata={"team": "P6-7", "bits_per_channel": test_bits, "message": "This signature will be corrupted."},
    )
    real_signature = sign_payload(PRIVATE_KEY, payload)

    # Flip the last byte so the signature no longer matches the payload,
    # while staying the same length (a structurally valid, but wrong, signature).
    corrupted_signature = real_signature[:-1] + bytes([real_signature[-1] ^ 0xFF])

    data_to_embed = pack_payload(payload, corrupted_signature)

    embed_payload(cover_path, output_path, data_to_embed, SECRET_KEY_PHRASE, bits_per_channel=test_bits)

    return render_template(
        'image_stego.html',
        signature_invalid_test_file=output_filename,
        signature_invalid_test_bits=test_bits,
    )


@bp.route('/generate-payload-missing-test', methods=['POST'])
def generate_payload_missing_test():
    """
    Demo/test utility: embeds deliberately non-JSON junk bytes (not a real
    payload+signature package) into a fresh cover image, using the exact same
    embed_payload() pipeline as a normal embed. The bytes authenticate
    correctly at the start-location/HMAC layer (so extraction succeeds), but
    fail to parse as a valid payload structure which is exactly what
    triggers the Payload Missing verdict on /verify.
    """
    cover_path = os.path.join(UPLOAD_FOLDER, "_tmp_cover_for_payload_missing.png")
    output_filename = "payload_missing_test.png"
    output_path = os.path.join(UPLOAD_FOLDER, output_filename)

    dummy_cover = Image.new("RGB", (200, 200), color=(120, 130, 140))
    dummy_cover.save(cover_path, "PNG")

    junk_bytes = b"this is not a valid JSON payload package at all"
    test_bits = 1

    embed_payload(cover_path, output_path, junk_bytes, SECRET_KEY_PHRASE, bits_per_channel=test_bits)

    return render_template(
        'image_stego.html',
        payload_missing_test_file=output_filename,
        payload_missing_test_bits=test_bits,
    )