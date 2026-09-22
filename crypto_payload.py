import hashlib
import json
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


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


if __name__ == "__main__":
    priv, pub = generate_keypair()

    cover_bytes = b"dummy cover object data"
    h = hash_cover_object(cover_bytes)
    payload = build_payload("IMG001", h, {"team": "P1-4"})
    sig = sign_payload(priv, payload)

    print("Payload:", payload)
    print("Verify (unmodified):", verify_payload(pub, payload, sig))  # True

    payload["metadata"]["team"] = "TAMPERED"
    print("Verify (tampered):", verify_payload(pub, payload, sig))  # False