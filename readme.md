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
2. Type the message to hide. This is used to demonstrate varying payload sizes,
   for example a short Learning Outcome, the full Project Overview paragraph, or a
   custom message.
3. Select number of LSBs to use (1-8).
4. System checks payload and authentication overhead against cover image capacity
   before proceeding.
5. Embed: payload (media ID, timestamp, hash, nonce, message) is built, signed
   with the app's private key, then hidden in the image starting at a key-derived
   start location.
6. Download the resulting stego image. Cover and stego are shown side by side for
   visual comparison.
7. Extract and verify: upload a stego image, either the same file or one received
   from someone else, with the matching bit depth. The system re-derives the start
   location, extracts the payload and signature, and returns a verdict. The
   filename checked is shown alongside the result.

### Start-location integration (FR7)

The keyed start-location scheme itself (`app/start_location.py`) is a shared
module, designed and owned by the teammate responsible for its cryptographic
design; see `start_location_notes.md` for the algorithm, API, and security
boundary in full detail. This section covers how that scheme behaves within the
image workflow specifically, which is what the image component builds on top of
and integrates against.

The payload is never embedded at a fixed position such as the top-left pixel.
Instead, at a high level:

- A shared secret key (`STEGO_SECRET_KEY`) is used to derive a starting position,
  combined with a random nonce generated fresh at each embed.
- A small bootstrap header (magic bytes, nonce, payload length) is written at a
  fixed, well-known offset, itself authenticated so it cannot be forged or
  guessed without the key even though its position is public.
- The verifier reads this header, checks its authenticity, and only then derives
  the actual location where the payload and its own authentication tag are
  hidden.
- Because both the header and the payload region are keyed and authenticated, an
  attacker without the secret key cannot locate, forge, or tamper with the hidden
  data undetected. Any attempt fails authentication and is reported as
  `Wrong Start Location`, rather than silently succeeding.

The image module (`app/image_stego.py`) calls into this shared scheme for every
embed and extract; the behaviors below describe what the image workflow
specifically produces as a result.

### Image verdict categories

- **Authentic**: payload extracted, signature valid, image hash matches. Verify an
  untampered stego image with the correct key and bit depth.
- **Tampered**: payload and location authenticate, but the image's content hash no
  longer matches. Edit pixels in a stego image after embedding, then verify.
- **Signature Invalid**: payload parses correctly, but its digital signature does
  not match. Not reliably producible by casual editing, since pixel tampering
  after embed typically breaks the start-location HMAC first. See Demo utilities
  below.
- **Payload Missing**: extracted bytes authenticate at the start-location layer,
  but do not parse as a valid payload structure. See Demo utilities below.
- **Wrong Start Location**: the bootstrap header does not authenticate, for
  example wrong key, wrong bit depth, or a file that was never embedded.
- **Cannot Verify**: the uploaded file is not a valid or readable image at all, for
  example a non-PNG file renamed with a `.png` extension.

### Image demo utilities

Because the start-location scheme is cryptographically authenticated rather than
a plain fixed offset, two of the six verdicts, Payload Missing and Signature
Invalid, cannot be reliably produced by casual editing of a real stego image. Any
pixel-level tampering tends to break the start-location HMAC first, which reports
as Wrong Start Location instead. To still demonstrate these two verdicts, the
Image page includes two one-click test utilities:

- **Generate "Payload Missing" Test File**: embeds deliberately non-JSON junk
  bytes through the real embedding pipeline. The bytes authenticate correctly at
  the start-location layer, proving the embed and extract mechanism itself works,
  but fail to parse as a valid payload structure.
- **Generate "Signature Invalid" Test File**: builds and signs a real payload
  normally, then flips one byte of the resulting signature before embedding. The
  payload is well-formed JSON and authenticates at the start-location layer, but
  the signature itself no longer matches.

Both utilities produce a normal PNG file that is then verified through the same
Verify flow as any other upload. No verification logic is bypassed or shortcut;
only the input to a normal embed is deliberately malformed, in a way that
isolates one verification layer at a time.


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
   `"authentic": false` and `"verdict": "Tampered"`. If a change damages the
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

### Audio wrong-start demo

Embed a fresh WAV with **1 LSB, start sample 100**. Extract the downloaded stego
WAV with **1 LSB, start sample 1**, using the matching trusted public key (or the
server default when embedded on the same server). Expect **Wrong Start Location**.
Change the extraction start back to **100** to obtain **Authentic**.

When the requested position has no valid packet header, audio scans sample LSBs
at the selected bit depth for another ASG1 packet. It reports Wrong Start Location
only when that packet's RSA signature verifies and its signed start/LSB metadata
matches the discovered position. A marker alone is not sufficient evidence.
This preserves existing audio files and manual start selection; it does not
implement the shared module's keyed start derivation or claim its innovation.

If no signed packet is confirmed, the result remains **Payload Missing**. A wrong
key, wrong LSB depth, or malformed payload can prevent confirmation. In particular,
the deliberately malformed `cannot_verify.wav` still returns **Cannot Verify** at
100 and **Payload Missing** at 1. Search is limited to 64 marker candidates and a
cumulative packet-byte budget equal to the PCM byte length; an inconclusive search
also returns Payload Missing. Out-of-range start values remain input errors.

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
