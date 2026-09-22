## Crypto/Payload Module (crypto_payload.py)

Install: `pip install -r requirements.txt`

Functions:
- `generate_keypair()` → (private_key, public_key)
- `hash_cover_object(data: bytes)` → sha256 hash (bytes)
- `build_payload(media_id: str, cover_hash: bytes, metadata: dict)` → payload dict
- `sign_payload(private_key, payload: dict)` → signature (bytes)
- `verify_payload(public_key, payload: dict, signature: bytes)` → True/False

Test: `python -m pytest -v`