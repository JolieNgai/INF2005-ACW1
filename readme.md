# INF2005 ACW1

**Team:** P6-7

## Overview

Flask web app that embeds signed verification payloads into PNG images and integer
PCM WAV audio using LSB replacement steganography. It extracts the hidden payload,
checks its RSA signature, and verifies the relevant media hash to detect tampering.

The home page links to **Image Steganography** at `/image` and **Audio Steganography**
at `/audio`. Both workflows use the persistent RSA keys in `app/keys/`.

## Requirements

- Docker Desktop (with Docker Compose)

## Setup

1. Clone the repository:
   ```
   git clone <repo-url>
   cd INF2005-ACW1
   ```

2. Create a `.env` file in the project root using `.env.example` as a template,
   and set the team's secret key:
   ```
   STEGO_SECRET_KEY=<key>
   ```
   The app will not start without this setting. Do not commit the local `.env` file.

3. Open Docker Desktop, then start the stack (Flask + gunicorn + nginx):
   ```
   docker compose up -d
   ```

4. Open the app:
   ```
   http://localhost:8080
   ```

## Project Structure

```
INF2005-ACW1/
├── app/
│   ├── __init__.py           # Flask app factory, blueprint registration, app-level error handler
│   ├── routes.py             # Home/image routes and persistent RSA keys
│   ├── audio_routes.py       # Audio page, embed/extract, capacity and tamper endpoints
|   ├── attack_routes.py      # Attack page, sweep execution and evidence downloads
│   ├── crypto_payload.py     # Hashing, payload building, signing/verification
│   ├── image_stego.py        # PNG LSB embed/extract logic
│   ├── audio_stego.py        # PCM WAV LSB embedding and audio verification
│   ├── audio_demo.py         # Generate sample WAVs and verification evidence
│   ├── attack_simulation.py  # Automated security attack simulation
│   ├── verdict.py            # Shared verdict vocabulary and error mapping
│   ├── validation.py         # Shared upload/input validation helpers
│   ├── test_audio_stego.py
│   ├── test_crypto_payload.py
│   ├── test_attack_simulation.py
│   ├── static/
│   └── templates/
├── examples/audio/      # Generated cover, stego, tampered WAVs and demo public key
├── evidence/
│   └── attack_results_<datetime>_SGT.json
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── nginx/
│   └── flask_app.conf
├── requirements.txt
└── run.py
```

## Dependencies

## Variable start-location module

`app/start_location.py` owns the shared keyed start-location scheme for images
and PCM audio samples. The PNG flow uses authenticated framing and reports
`Wrong Start Location` on location/frame authentication failure. Existing
images made with the old format must be embedded again. See
[start_location_notes.md](start_location_notes.md) for the algorithm, API,
sole ownership statement, audio integration contract, and security limits.

## Usage
See `requirements.txt`. Key packages: Flask, gunicorn, cryptography, Pillow,
python-dotenv, and pytest. Docker installs these when building the app image.
After dependency changes, rebuild once with `docker compose up -d --build`;
normal startup remains `docker compose up -d`.

## Image usage

1. Upload a PNG cover image.
2. Select number of LSBs to use (1–8).
3. System checks payload capacity against cover image size.
4. Embed: payload is signed, then hidden in image starting at a derived start location.
5. Extract: recover payload + signature from a stego image, verify authenticity.

## Audio usage and demo

Open http://localhost:8080/audio, or select **Audio Steganography** on the home page.

1. Under **Embed**, upload an integer PCM WAV. For a repeatable demo, use
   `examples/audio/cover.wav`, **1 LSB**, and **start sample 100**. Enter a message,
   such as: `Explain how steganography can be used to embed hidden verification data.`
2. Click **Check capacity**, then **Embed and sign**. Capacity includes the framing
   header, metadata, and signature as well as the message. Embedding is rejected
   if the complete packet does not fit.
3. Play **Cover** and **Stego** to compare them. Download `stego.wav` and
   `public-key.pem`. Use 16-bit PCM and 1–2 LSBs for the listening comparison;
   higher settings may introduce audible noise.
4. Under **Extract and verify**, upload the downloaded `stego.wav`, select the
   same LSB setting and start sample, and click **Extract and verify**. The saved
   server public key is used by default. Upload the matching trusted public key
   when verifying audio from another instance or the standalone demo.
   Expect `"authentic": true`, `"verdict": "Authentic"`, and the recovered message.
5. Under **Tampered-audio negative case**, upload that same stego WAV, click
   **Create tampered WAV**, and download `tampered.wav`. This changes one audio sample.
6. Verify `tampered.wav` using the same key and settings. Expect
   `"authentic": false` and `"verdict": "Tampered audio"`. If a change damages the
   hidden packet itself, extraction or signature verification may fail instead.

The hidden message can remain readable after audio tampering; this does not mean
verification passed. Check the `authentic` flag and verdict. Keep each stego file
with its matching public key, and capture both positive and negative results for
demo evidence.

### Generate sample audio

With the Docker stack running:

```powershell
docker compose exec web python -m app.audio_demo
```

This generates a three-second tone and writes `cover.wav`, `stego.wav`,
`tampered.wav`, `public-key.pem`, and `verification.json` to `examples/audio/`.
Use **1 LSB, start sample 100**, and explicitly upload that folder's public key
when verifying the generated examples. The demo uses its own key pair, separate
from the web app's persistent keys. Rerunning it replaces the generated files.

### How audio embedding and verification work

`app/audio_stego.py` reads WAV frames using Python's `wave` module. It replaces
the selected **1–8 low bits per PCM sample**, starting at the chosen sample index.
Samples are counted across interleaved channels. Sample width, sample rate,
channel count, and frame count are preserved.

Total packet capacity in bytes is:

```text
floor((sample_count - start_sample) * bits_per_sample / 8)
```

The packet has an eight-byte header (`ASG1` marker plus a four-byte body length)
followed by JSON containing the payload and a base64 RSA signature. Bits are
stored least-significant first. Extraction validates the length against available
capacity before reading the packet.

The existing crypto module builds the payload with a media ID, timestamp, nonce,
SHA-256 hash, and metadata containing the message, LSB count, and start sample.
The app signs it using RSA-PSS and the existing private key. Audio verification
uses the saved public key or an explicitly supplied trusted public key; it never
trusts a key embedded inside the audio itself.

Embedding changes audio bits, so hashing the untouched cover directly would make
verification fail immediately. Instead, the hash clears exactly the bits occupied
by the packet before hashing the remaining PCM data and audio format fields.
The same operation is applied during verification. The signature protects the
payload, while the hash detects edits outside it, including unused low bits.

## Tests

With the Docker stack running:

```powershell
docker compose exec web python -m pytest -q
```

Audio tests cover all eight LSB settings, 8/16/24/32-bit samples, mono/stereo,
Unicode messages, capacity boundaries, invalid input, wrong keys/settings,
header/payload corruption, PCM changes, sample-rate changes, persistent signing
keys, and Flask routes. An image embed/verify regression test checks integration
with the existing image workflow.

### Demo outcomes

- **Positive case:** unmodified stego image → extraction succeeds → signature verifies → Authentic.
- **Negative case (tampered):** stego image modified after embedding → verification fails → Tampered.
- **Audio positive:** unmodified stego WAV with matching settings/key → Authentic.
- **Audio negative:** sample modified after embedding → Tampered audio, or an
  extraction/signature failure if the hidden packet is damaged.

## Known Limitations

- Audio start samples are selectable and signed but are not secret or derived
  from `STEGO_SECRET_KEY`. Share the LSB setting and start sample with the receiver.
- Steganography hides the message; it does **not encrypt** it. Anyone knowing or
  guessing the settings can read it. Keep private keys secret and distribute
  public keys through a trusted channel.
- Audio sample changes are bounded by `2**bits - 1`. Audibility depends on the
  recording and sample width; eight LSBs on 8-bit audio can substantially degrade
  it. Automated tests do not replace a listening comparison.
- Audio requires uncompressed integer PCM WAV. Floating-point or compressed WAVs
  are rejected. Lossy conversion, resampling, or editing generally breaks
  verification. Browser playback support varies; use 16-bit PCM for the demo.
- Original overwritten audio bits cannot be reconstructed. Non-audio RIFF
  metadata is not authenticated, and ancillary chunks are not retained when
  writing WAVs.
- Requests are limited to 20 MiB, matching nginx. Audio files are processed in
  memory and are not retained by the audio endpoints.

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

```powershell
docker compose exec web python -m app.crypto_payload
```

## Orchestration & Error Handling (app/verdict.py, app/__init__.py)

- `Verdict` enum defines the six verdict categories from FR10, used as the shared
  vocabulary across image and audio:
  - `Authentic` — signature valid, hash matches
  - `Tampered` — signature valid, hash mismatch
  - `Signature Invalid` — signature check fails
  - `Payload Missing` — no payload could be extracted
  - `Wrong Start Location` — extraction at the derived offset yields no valid payload
  - `Cannot Verify` — unsupported file, missing dependency module, or unexpected error
- `verdict_from_exception(exc)` maps unexpected exceptions to `Cannot Verify` with
  an explanation, instead of leaking a raw stack trace to the user.
- An app-level error handler in `__init__.py` catches any unhandled exception from
  any blueprint (image, audio, or home) and returns either a styled HTML error page
  or a JSON error response depending on the request path, so the app stays usable
  instead of showing a raw traceback.
- Client-side state management (disabling submit buttons during a request, showing
  a processing state) is implemented for both the image workflow (inline script in
  `image_stego.html`) and the audio workflow (`audio.js`).
- Shared input validation (`app/validation.py`) is used on the image routes to
  reject invalid/missing files and out-of-range LSB values before they reach the
  stego modules.

## Attack Simulation Module (`app/attack_simulation.py`)

Runs automated negative-case security tests against the crypto, image-steganography,
and audio-steganography modules. Each scenario records its expected and actual
verification result in a timestamped JSON evidence report.

**Current scenarios:**
**Crypto/Payload tests:**
- Valid payload baseline
- Payload corruption
- Wrong public key
- Corrupted signature

**Image-steganography tests:**
- Valid stego-image baseline
- Embedded payload corruption
- Wrong public key
- Corrupted embedded signature
- Wrong start-location key
- Cover-image pixel tampering
- Oversized payload rejection
- Explicit wrong start-index extraction
- Authenticated bootstrap-header tampering

**Audio-steganography tests:**
- Valid stego-audio baseline
- Embedded payload corruption
- Wrong public key
- Corrupted embedded signature
- Wrong start location
- Audio-sample tampering
- Oversized payload rejection

The suite currently runs 20 scenarios: 3 positive baselines and 17 negative cases.

**Run from the website:**

Open http://localhost:8080/attack-simulation, click Run Attack Simulation,
then review the results table. Select Download CSV Evidence for an
Excel-friendly report or Download JSON Evidence for the complete structured
record.

**Run automated tests:**

```
docker compose run --rm web pytest -q app/test_attack_simulation.py
```

Expected result: 5 passed. These five pytest functions validate the crypto,
image and audio sweeps, combined evidence generation, and the web run/download
flow.

**Run attack simulation:**

```
docker compose run --rm web python -m app.attack_simulation
```

The command displays each scenario’s verification result and creates a new evidence file:

evidence/attack_results_YYYYMMDD_HHMMSS_microseconds_SGT.json

Each JSON report contains the Singapore generation time, test summary, expected and actual results, attack-detection status, and an explanation of each scenario.
