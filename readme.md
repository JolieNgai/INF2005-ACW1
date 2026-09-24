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

2. Create a `.env` file in the project root:
   ```
   STEGO_SECRET_KEY=<key>
   ```
   The app will not start without this

3. Build and start the stack (Flask + gunicorn + nginx):
   ```
   docker compose up --build
   ```

4. Open the app:
   ```
   http://localhost:8080
   ```

## Project Structure
```
INF2005-ACW1/
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── routes.py                   # Web routes, orchestration, error handling
│   ├── crypto_payload.py           # Hashing, payload building, signing/verification
│   ├── image_stego.py              # LSB embed/extract logic
│   ├── attack_simulation.py        # Automated security attack simulation
│   ├── test_attack_simulation.py   # Attack-simulation automated tests
│   ├── verdict.py                  # Shared verdict vocabulary, error-to-verdict mapping
│   ├── validation.py               # Shared upload/input validation helpers
│   ├── static/
│   └── templates/
├── evidence/
│   └── attack_results_<datetime>_SGT.json
├── Dockerfile
├── docker-compose.yml
├── nginx/
│   └── flask_app.conf
├── requirements.txt
└── run.py
```

## Dependencies
See `requirements.txt`. Key packages: Flask, gunicorn, cryptography, Pillow, python-dotenv.

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

## Orchestration & Error Handling (app/verdict.py, app/routes.py)

- `Verdict` enum defines the six verdict categories from FR10, used as the shared
  vocabulary across modules:
  - `Authentic` — signature valid, hash matches
  - `Tampered` — signature valid, hash mismatch
  - `Signature Invalid` — signature check fails
  - `Payload Missing` — no payload could be extracted
  - `Wrong Start Location` — extraction at the derived offset yields no valid payload
  - `Cannot Verify` — unsupported file, missing dependency module, or unexpected error
- `verdict_from_exception(exc)` maps unexpected exceptions (including calls to
  not-yet-implemented modules) to `Cannot Verify` with an explanation, instead of
  leaking a raw stack trace to the user.
- A blueprint-level error handler in `routes.py` catches any unhandled exception raised
  inside a route and renders it via `home.html` with a clear error message, so the app
  stays usable instead of showing a raw traceback.

## Attack Simulation Module (`app/attack_simulation.py`)

Runs automated attacks against the crypto/payload module and records the expected and actual verification results.

**Current scenarios:**

- Valid payload baseline
- Payload corruption
- Wrong public key
- Corrupted signature
- Replay attempt
- Signed-payload substitution

**Run automated tests:**

```bash
docker compose run --rm web pytest -q app/test_attack_simulation.py
```

**Run attack simulation:**

```bash
docker compose run --rm web python -m app.attack_simulation
```

The command displays each scenario’s verification result and creates a new evidence file:

```text
evidence/attack_results_YYYYMMDD_HHMMSS_microseconds_SGT.json
```

Each JSON report contains the Singapore generation time, test summary, expected and actual results, attack-detection status, and an explanation of each scenario.
