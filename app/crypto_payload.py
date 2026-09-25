import hashlib
import json
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_keypair():
    """Generate an RSA private/public keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def hash_cover_object(data: bytes) -> bytes:
    """SHA-256 hash of cover object bytes (image, audio, or dummy data)."""
    return hashlib.sha256(data).digest()


def build_payload(media_id: str, cover_hash: bytes, metadata: dict) -> dict:
    """Build a verification payload with media ID, timestamp, hash, nonce, metadata."""
    return {
        "media_id": media_id,
        "timestamp": int(time.time()),
        "hash": cover_hash.hex(),
        "nonce": secrets.token_hex(8),
        "metadata": metadata,
    }


def _serialize(payload: dict) -> bytes:
    """Deterministic serialization so sign/verify always match on identical payloads."""
    return json.dumps(payload, sort_keys=True).encode()


def sign_payload(private_key, payload: dict) -> bytes:
    """Sign the payload with the private key using RSA-PSS + SHA-256."""
    return private_key.sign(
        _serialize(payload),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_payload(public_key, payload: dict, signature: bytes) -> bool:
    """Verify the payload signature with the public key. Returns True/False."""
    try:
        public_key.verify(
            signature,
            _serialize(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def stable_hash(pixel_bytes: bytes, bits_per_channel: int) -> bytes:
    """
    SHA-256 of the image with the bottom `bits_per_channel` bits of every
    channel zeroed out. Invariant to legitimate LSB embedding at that same
    bit-depth, but changes if anything else about the image is altered.
    """
    mask = (~((1 << bits_per_channel) - 1)) & 0xFF
    masked = bytes(b & mask for b in pixel_bytes)
    return hashlib.sha256(masked).digest()


def run_verification(stego_path, key, bits, public_key, unpack_payload_fn, extract_payload_fn):
    """
    Pure function: given a stego file path, returns (verdict, payload_dict_or_None).
    No Flask/HTTP dependency, so this can be unit-tested or reused by a CLI/tamper test.
    """
    from PIL import Image
    from .start_location import WrongStartLocationError

    try:
        img = Image.open(stego_path).convert("RGB")
        extracted_bytes = extract_payload_fn(stego_path, key, bits_per_channel=bits)
    except WrongStartLocationError:
        return "Wrong Start Location", None
    except Exception:
        return "Cannot Verify", None

    try:
        payload, signature = unpack_payload_fn(extracted_bytes)
    except Exception:
        return "Payload Missing", None

    if not verify_payload(public_key, payload, signature):
        return "Signature Invalid", None

    recomputed_hash = stable_hash(img.tobytes(), bits).hex()
    if recomputed_hash != payload["hash"]:
        return "Tampered", payload

    return "Authentic", payload

if __name__ == "__main__":
    priv, pub = generate_keypair()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print("=== Generated Keypair ===")
    print(priv_bytes.decode())
    print(pub_bytes.decode())

    # --- Case 1: Positive verification (before tampering) ---
    cover_bytes = b"dummy cover object data"
    h = hash_cover_object(cover_bytes)
    payload = build_payload("IMG001", h, {"team": "P6-7"})
    sig = sign_payload(priv, payload)

    print("=== BEFORE tampering ===")
    print("Payload:", payload)
    print("Verify:", verify_payload(pub, payload, sig))  # True

    # --- Case 2: Tampered payload ---
    payload["metadata"]["team"] = "TAMPERED"
    print("=== AFTER tampering ===")
    print("Payload:", payload)
    print("Verify:", verify_payload(pub, payload, sig))  # False

    # --- Case 3: Corrupted signature (payload untouched) ---
    fresh_payload = build_payload("IMG002", h, {"team": "P1-4"})
    fresh_sig = sign_payload(priv, fresh_payload)
    corrupted_sig = fresh_sig[:-1] + bytes([fresh_sig[-1] ^ 0xFF])  # flip last byte
    print("=== Verify (corrupted signature) ===")
    print(verify_payload(pub, fresh_payload, corrupted_sig))  # False

    # --- Case 4: Payload missing ---
    print("=== Verify (missing payload) ===")
    print(verify_payload(pub, {}, fresh_sig))  # False

    # --- Case 5: Varying payload sizes (short vs large message) ---
    short_note = "Explain how steganography can be used to embed hidden verification data."
    large_note = (
        "This undergraduate project requires student teams to design, implement and "
        "demonstrate a GUI-based LSB Replacement steganography program that protects "
        "and verifies both image and audio cover objects using steganography, hashing "
        "and digital signatures."
    )

    short_payload = build_payload("IMG003", h, {"note": short_note})
    short_sig = sign_payload(priv, short_payload)
    print("=== Verify (short payload) ===")
    print(verify_payload(pub, short_payload, short_sig))  # True

    large_payload = build_payload("IMG003", h, {"note": large_note})
    large_sig = sign_payload(priv, large_payload)
    print("=== Verify (large payload) ===")
    print(verify_payload(pub, large_payload, large_sig))  # True
