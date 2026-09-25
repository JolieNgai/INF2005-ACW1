# INF2005 ACW1

**Team:** P6-7


## Overview
GUI-based tool (Flask web app) that embeds a signed verification payload into a PNG cover
image using LSB replacement steganography, then verifies authenticity by extracting the
payload and checking its digital signature against tampering.

## Requirements
- Docker Desktop (with Docker Compose)

## Setup

1. Clone the repository:
   ```
   git clone <repo-url>
   cd INF2005-ACW1
   ```

2. Build and start the stack (Flask + gunicorn + nginx):
   ```
   docker compose up --build
   ```

3. Open the app:
   ```
   http://localhost:8080
   ```

## Project Structure
```
INF2005-ACW1/
├── app/
│   ├── __init__.py       # Flask app factory
│   ├── routes.py         # Web routes
│   ├── crypto_payload.py # Hashing, payload building, signing/verification
│   ├── image_stego.py    # LSB embed/extract logic
│   ├── static/
│   └── templates/
├── Dockerfile
├── docker-compose.yml
├── nginx/
│   └── flask_app.conf
├── requirements.txt
└── run.py
```

## Dependencies
See `requirements.txt`. Key packages: Flask, gunicorn, cryptography, Pillow.

## Variable start-location module

`app/start_location.py` owns the shared keyed start-location scheme for images
and PCM audio samples. The PNG flow uses authenticated framing and reports
`Wrong Start Location` on location/frame authentication failure. Existing
images made with the old format must be embedded again. See
[start_location_notes.md](start_location_notes.md) for the algorithm, API,
sole ownership statement, audio integration contract, and security limits.

## Usage
1. Upload a PNG cover image.
2. Select number of LSBs to use (1–8).
3. System checks payload capacity against cover image size.
4. Embed: payload is signed, then hidden in image starting at a derived start location.
5. Extract: recover payload + signature from a stego image, verify authenticity.

## Test Cases
- **Positive case:** unmodified stego image → extraction succeeds → signature verifies → Authentic.
- **Negative case (tampered):** stego image modified after embedding → verification fails → Tampered.

## Known Limitations
(to be filled in as development progresses — e.g. LSB fragility to compression/resaving,
lossless PNG requirement, capacity ceiling per image size)


## Crypto/Payload Module (app/crypto_payload.py)

Handles payload construction, hashing, signing, and signature verification.

**Functions:**
- `generate_keypair()` → (private_key, public_key)
- `hash_cover_object(data: bytes)` → SHA-256 hash of cover object bytes
- `build_payload(media_id: str, cover_hash: bytes, metadata: dict)` → payload dict (media_id, timestamp, hash, nonce, metadata)
- `sign_payload(private_key, payload: dict)` → signature (bytes), RSA-PSS + SHA-256
- `verify_payload(public_key, payload: dict, signature: bytes)` → True/False

**Run standalone demo:**
    python crypto_payload.py
