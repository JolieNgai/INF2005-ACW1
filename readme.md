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
