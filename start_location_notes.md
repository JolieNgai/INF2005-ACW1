# Variable start-location scheme — single ownership

The team member responsible for `app/start_location.py` is the sole owner of
the project's variable start-location design, implementation, wrong-location
detection, and associated innovation claim. Image/audio adapters consume this
module; they do not duplicate or separately claim its derivation algorithm.
RSA signatures and cover hashing remain the crypto/payload module's concern.

Suggested project contribution statement:

> Designed and implemented a shared, nonce-varying, keyed pseudo-random
> start-location scheme for image channels and PCM audio samples, with
> authenticated decoder recovery and wrong-location detection.

This is a project-level design contribution, not a claim to have invented HMAC
or a new cryptographic primitive. Add the responsible member's name in the
team's contribution table.

## Encoding and recovery

1. Describe the carrier with `CarrierSpec.image(...)` or `CarrierSpec.audio(...)`.
   Image units are RGB channel values in row order; audio units are interleaved
   PCM samples, not bytes from a WAV header. Both sides use identical parameters.
2. The encoder generates a fresh 128-bit random nonce. HMAC-SHA256 binds that
   nonce to the key, media type, dimensions/sample rate, sample width, and LSB
   depth. Rejection sampling maps its output uniformly into the usable region.
3. A fixed bootstrap stores `SL01` (4 bytes), nonce (16), payload length (8,
   big endian), and a full header HMAC (32). It occupies `ceil(480 / bits)` units
   at index zero. The derived start index itself is never stored.
4. Payload plus a 32-byte HMAC starts at the derived index, wrapping around only
   within the region after the bootstrap. Separate HMAC subkeys are derived
   for location, header authentication, and payload authentication.
5. The decoder authenticates the bootstrap before trusting its length, checks
   capacity, re-derives the start, reads bounded data, and authenticates the
   payload. Payload authentication also binds the header and start index.

Header and payload sections are independently padded to whole carrier units.
Capacity accounting includes this padding and all 92 bytes of framing overhead.
This also handles LSB depths 3, 5, 6, and 7 without losing bits at section borders.

## API

```python
from app.start_location import CarrierSpec, embed_units, extract_units

# Audio adapter example: one second of stereo, signed 16-bit PCM at 44.1 kHz.
# A WAV reader supplies these decoded, interleaved integer samples.
spec = CarrierSpec.audio(frames=44100, channels=2, sample_rate=44100,
                         sample_width=16, bits=2)
samples = [-12345, 12345] * 44100
key = bytes.fromhex("YOUR_64_HEX_CHARACTER_RANDOM_SECRET")
stego_samples = embed_units(samples, b"signed payload bytes", key, spec)
assert extract_units(stego_samples, key, spec) == b"signed payload bytes"
```

PCM sample widths 8, 16, 24, and 32 are supported with 1–8 LSBs per sample.
Audio file reading/writing and an audio web page are not present in this project;
the audio adapter must preserve sample order, width, rate, channels, and exact
integer values. Lossy audio formats are unsuitable. The existing PNG adapter
is integrated with the same APIs.

Low-level encoder selection: `select_start_location(key, spec, payload_size)`
returns `(start_index, authenticated_header)`. Decoder recovery:
`recover_start_location(key, spec, header)` returns `(start_index, payload_size)`.
`derive_start_location(key, spec, nonce)` is deterministic for matching inputs.
`extract_units(..., start_index=...)` optionally validates an externally supplied
index; normally the decoder recovers the index automatically.

## Detection and security limits

- `WrongStartLocationError` covers a wrong key, wrong settings, wrong supplied
  index, absent frame, and modified header/payload. The image verification flow
  displays **Wrong Start Location**. It cannot prove which cause occurred.
- Use a high-entropy random shared secret, such as `secrets.token_hex(32)`, in
  `STEGO_SECRET_KEY`. The API accepts existing strings for compatibility but
  does not enforce entropy or stretch passwords. The public header enables
  offline password guesses if a weak phrase is used.
- A fresh nonce varies the location for repeated embeddings; finite carrier
  positions can still collide. Guessing or scanning a location is possible.
  Authentication prevents an attacker without the key from producing a valid
  replacement frame; location secrecy alone is not a security guarantee.
- Payloads are not encrypted. The bootstrap is at a known location. This is
  not a guarantee of undetectable steganography, confidentiality, or resistance
  to an attacker destroying the embedded bits.
- Unused carrier units and their high bits are not authenticated here. The
  existing signed stable-cover hash handles image integrity separately. At
  8-bit image LSB depth no high bits remain for that hash to protect. Full
  carrier copying/replay is not prevented by this scheme.
- This is a new format. Images embedded by the old four-byte-length scheme
  must be embedded again; there is no unauthenticated legacy fallback.

HMAC authentication uses constant-time tag comparison as recommended by the
[Python HMAC documentation](https://docs.python.org/3.11/library/hmac.html).

## Validation

Run `docker compose exec -T web python -m pytest -q` with the web container up.
Tests cover image/PCM recovery at all eight LSB depths, preservation of upper
bits, PNG save/reload, fresh nonces, wrong keys/settings/indices, header and
payload tampering, wraparound, exact capacity, empty payloads, absent data, and
the displayed verification verdict.
