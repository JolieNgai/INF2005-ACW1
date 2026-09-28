import hashlib
import json
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from .verdict import Verdict

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
    Pure function: given a stego file path, returns (Verdict, payload_dict_or_None).
    No Flask/HTTP dependency, so this can be unit-tested or reused by a CLI/tamper test.
    """
    from PIL import Image
    from .start_location import PayloadMissingError, WrongStartLocationError

    try:
        img = Image.open(stego_path).convert("RGB")
        extracted_bytes = extract_payload_fn(stego_path, key, bits_per_channel=bits)
    except PayloadMissingError:
        return Verdict.PAYLOAD_MISSING, None
    except WrongStartLocationError:
        return Verdict.WRONG_START_LOCATION, None
    except Exception:
        return Verdict.CANNOT_VERIFY, None

    try:
        payload, signature = unpack_payload_fn(extracted_bytes)
    except Exception:
        return Verdict.PAYLOAD_MISSING, None

    if not verify_payload(public_key, payload, signature):
        return Verdict.SIGNATURE_INVALID, None

    recomputed_hash = stable_hash(img.tobytes(), bits).hex()
    if recomputed_hash != payload["hash"]:
        return Verdict.TAMPERED, payload

    return Verdict.AUTHENTIC, payload

if __name__ == "__main__":
    def step(title):
        print(f"\n======== {title} ========")

    def pause():
        input("\n[Press Enter to continue]")

    note = input("Enter a message to sign: ")

    # 1. Keys
    priv, pub = generate_keypair()
    step("1. Generate RSA-2048 key pair")
    print("Private key: generated (kept secret, not printed)")
    print(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode())
    pause()

    # 2. Hash
    step("2. Hash the cover object (SHA-256)")
    cover_bytes = b"dummy cover object data"
    h = hash_cover_object(cover_bytes)
    print("Cover bytes:", cover_bytes)
    print("SHA-256    :", h.hex())
    pause()

    # 3. Build payload
    step("3. Build payload")
    payload = build_payload("IMG001", h, {"team": "P6-7", "note": note})
    print(json.dumps(payload, indent=2))
    pause()

    # 4. Serialize
    step("4. Serialize payload to bytes")
    print(_serialize(payload))
    pause()

    # 5. Sign
    step("5. Sign with private key (RSA-PSS + SHA-256)")
    sig = sign_payload(priv, payload)

    
    print("Signature length:", len(sig), "bytes")
    print("Signature (hex, first 64 chars):", sig.hex()[:64] + "...")
    pause()

    # 6. Verify untouched
    step("6. Verify with public key (untouched)")
    print("Result:", verify_payload(pub, payload, sig))  # True
    pause()

    # 7. Tamper payload
    step("7. Tamper with payload after signing")
    tampered = json.loads(json.dumps(payload))
    tampered["metadata"]["note"] = "goodbye world"
    print("Before:", payload["metadata"])
    print("After :", tampered["metadata"])
    print("Result:", verify_payload(pub, tampered, sig))  # False

