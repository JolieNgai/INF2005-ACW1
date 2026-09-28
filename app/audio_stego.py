"""PCM WAV adapter for the shared authenticated start-location format."""
import base64
import hashlib
import io
import json
import struct
import wave

from .crypto_payload import build_payload, sign_payload, verify_payload
from .verdict import Verdict
from .start_location import (
    CarrierSpec, HEADER_BYTES, TAG_BYTES, PayloadMissingError, WrongStartLocationError,
    select_start_location, recover_start_location, embed_units, extract_units,
    required_units, _read, derive_payload_positions, _units,
)


def read_wav(data):
    try:
        with wave.open(io.BytesIO(data), 'rb') as wav:
            params = wav.getparams()
            frames = wav.readframes(params.nframes)
        if (params.comptype != 'NONE' or params.sampwidth not in (1, 2, 3, 4)
                or len(frames) != params.nframes * params.nchannels * params.sampwidth
                or not frames):
            raise ValueError('Empty, truncated, or unsupported PCM audio.')
        return params, frames
    except (wave.Error, EOFError, struct.error) as exc:
        raise ValueError('Upload an uncompressed integer PCM WAV file (8/16/24/32-bit).') from exc


def write_wav(params, frames):
    output = io.BytesIO()
    with wave.open(output, 'wb') as wav:
        wav.setparams(params)
        wav.writeframes(frames)
    return output.getvalue()


def _spec(params, bits):
    if type(bits) is not int or not 1 <= bits <= 8:
        raise ValueError('Select 1 to 8 LSBs.')
    return CarrierSpec.audio(params.nframes, params.nchannels, params.framerate,
                             params.sampwidth * 8, bits)


def _samples(params, frames):
    width = params.sampwidth
    return [int.from_bytes(frames[i:i + width], 'little', signed=width != 1)
            for i in range(0, len(frames), width)]


def _frames(params, samples):
    return b''.join(value.to_bytes(params.sampwidth, 'little', signed=params.sampwidth != 1)
                    for value in samples)


def capacity(wav_bytes, bits=1):
    """Maximum signed JSON envelope bytes after shared framing and padding."""
    params, _ = read_wav(wav_bytes)
    spec = _spec(params, bits)
    return max(0, (spec.total_units - spec.header_units) * bits // 8 - TAG_BYTES)


def _packet(payload, signature):
    return json.dumps({'payload': payload, 'signature': base64.b64encode(signature).decode()},
                      sort_keys=True, separators=(',', ':')).encode()


def _audio_hash(params, frames, spec, key, nonce, packet_size):
    # Shared _write overwrites every chosen LSB, including alignment padding.
    # Normalize exactly those units: bootstrap plus scattered payload + HMAC.
    # All other bits, including unused low bits, remain protected by the hash.
    normalized = bytearray(frames)
    mask = 255 ^ ((1 << spec.bits_per_unit) - 1)
    for index in range(spec.header_units):
        normalized[index * params.sampwidth] &= mask
    for index in derive_payload_positions(key, spec, nonce, _units(packet_size + TAG_BYTES, spec.bits_per_unit)):
        normalized[index * params.sampwidth] &= mask
    return hashlib.sha256(spec.context() + b'\x00' + normalized).digest()


def embed(wav_bytes, message, private_key, bits=1, *, key, media_id='AUDIO001', demo_log=None):
    params, frames = read_wav(wav_bytes)
    spec = _spec(params, bits)
    available = capacity(wav_bytes, bits)
    payload = build_payload(media_id, bytes(32), {'message': message, 'bits': bits})
    size = len(_packet(payload, bytes(private_key.key_size // 8)))
    if required_units(size, spec) > spec.total_units:
        raise ValueError(f'Capacity exceeded: signed payload needs {size} bytes; audio holds {available} bytes after framing.')
    start, header = select_start_location(key, spec, size)
    payload['hash'] = _audio_hash(params, frames, spec, key, header[4:20], size).hex()
    packet = _packet(payload, sign_payload(private_key, payload))
    samples = embed_units(_samples(params, frames), packet, key, spec,
                          prepared_header=header, demo_log=demo_log)
    return write_wav(params, _frames(params, samples)), {
        'required_bytes': size, 'capacity_bytes': available,
        'required_samples': required_units(size, spec), 'start_index': start,
    }


def extract(wav_bytes, public_key, bits=1, *, key, start=None, demo_log=None):
    params, frames = read_wav(wav_bytes)
    spec = _spec(params, bits)
    samples = _samples(params, frames)
    try:
        packet = extract_units(samples, key, spec, start_index=start, demo_log=demo_log)
    except (PayloadMissingError, WrongStartLocationError) as exc:
        verdict = Verdict.PAYLOAD_MISSING if isinstance(exc, PayloadMissingError) else Verdict.WRONG_START_LOCATION
        if demo_log:
            demo_log(f'UPLOAD RECOVERY FAILED | {exc}')
        return {'authentic': False, 'verdict': verdict.value}
    header = _read(samples, HEADER_BYTES, spec, 0, bootstrap=True)
    recovered, length = recover_start_location(key, spec, header)
    try:
        envelope = json.loads(packet)
        payload = envelope['payload']
        signature = base64.b64decode(envelope['signature'], validate=True)
        if not isinstance(payload, dict) or not verify_payload(public_key, payload, signature):
            return {'authentic': False, 'verdict': Verdict.SIGNATURE_INVALID.value}
        expected = _audio_hash(params, frames, spec, key, header[4:20], length).hex()
        valid = payload['hash'] == expected and payload['metadata']['bits'] == bits
        return {'authentic': valid,
                'verdict': Verdict.AUTHENTIC.value if valid else Verdict.TAMPERED.value,
                'payload': payload, 'start_index': recovered}
    except (ValueError, KeyError, TypeError, UnicodeError):
        return {'authentic': False, 'verdict': Verdict.CANNOT_VERIFY.value}


def corrupt_payload(wav_bytes, bits=1, *, key, start=None):
    """Create an authenticated SL02 frame with malformed JSON for a demo.

    The server deliberately recomputes the HMAC using its secret so the fixture
    reaches JSON validation. An attacker without that key cannot do this.
    """
    params, frames = read_wav(wav_bytes)
    spec = _spec(params, bits)
    samples = _samples(params, frames)
    packet = extract_units(samples, key, spec, start_index=start)
    try:
        envelope = json.loads(packet)
        if not isinstance(envelope['payload'], dict) or not isinstance(envelope['signature'], str):
            raise ValueError('Invalid payload')
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ValueError('The hidden payload is already malformed. Upload an uncorrupted stego WAV.') from exc
    header = _read(samples, HEADER_BYTES, spec, 0, bootstrap=True)
    # Same length and nonce preserve the exact scattered layout. Only the first
    # JSON byte and the recomputed HMAC change; RSA validation is never bypassed.
    damaged = b'\x00' + packet[1:]
    output = embed_units(samples, damaged, key, spec, prepared_header=header)
    return write_wav(params, _frames(params, output))

def tamper(wav_bytes):
    """Change a high PCM bit for a reproducible negative demo."""
    params, frames = read_wav(wav_bytes)
    changed = bytearray(frames)
    changed[-1] ^= 128
    return write_wav(params, changed)
