"""LSB replacement in integer PCM samples, with signed audio verification."""
import base64
import hashlib
import io
import json
import struct
import wave

from .crypto_payload import build_payload, sign_payload, verify_payload
from .verdict import Verdict

HEADER = struct.Struct('>4sI')
MAGIC = b'ASG1'


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


def _capacity(params, bits, start):
    samples = params.nframes * params.nchannels
    if type(bits) is not int or not 1 <= bits <= 8:
        raise ValueError('Select 1 to 8 LSBs.')
    if type(start) is not int or not 0 <= start < samples:
        raise ValueError('Start sample must be within the audio.')
    return (samples - start) * bits // 8


def capacity(wav_bytes, bits=1, start=0):
    """Total packet capacity, including header, JSON and signature overhead."""
    params, _ = read_wav(wav_bytes)
    return _capacity(params, bits, start)


def _packet(payload, signature):
    body = json.dumps({'payload': payload, 'signature': base64.b64encode(signature).decode()},
                      sort_keys=True, separators=(',', ':')).encode()
    return HEADER.pack(MAGIC, len(body)) + body


def _audio_hash(params, frames, bits, start, packet_size):
    # Only erase bits actually occupied by the packet. All other PCM bits remain
    # covered, including unused low bits and the final sample's padding bits.
    normalized = bytearray(frames)
    for offset in range(0, packet_size * 8, bits):
        used = min(bits, packet_size * 8 - offset)
        index = (start + offset // bits) * params.sampwidth
        normalized[index] &= 255 ^ ((1 << used) - 1)
    description = struct.pack('>IIIII', params.nchannels, params.sampwidth,
                              params.framerate, params.nframes, bits)
    return hashlib.sha256(description + normalized).digest()


def embed(wav_bytes, message, private_key, bits=1, start=0, media_id='AUDIO001'):
    params, frames = read_wav(wav_bytes)
    available = _capacity(params, bits, start)
    payload = build_payload(media_id, bytes(32),
                            {'message': message, 'bits': bits, 'start': start})
    # RSA signatures and the hexadecimal hash have fixed sizes.
    size = len(_packet(payload, bytes(private_key.key_size // 8)))
    if size > available:
        raise ValueError(f'Capacity exceeded: packet needs {size} bytes; audio holds {available} bytes.')
    payload['hash'] = _audio_hash(params, frames, bits, start, size).hex()
    packet = _packet(payload, sign_payload(private_key, payload))
    output = bytearray(frames)
    for offset in range(0, len(packet) * 8, bits):
        used = min(bits, len(packet) * 8 - offset)
        value = sum(((packet[(offset + bit) // 8] >> ((offset + bit) % 8)) & 1) << bit
                    for bit in range(used))
        index = (start + offset // bits) * params.sampwidth
        output[index] = (output[index] & (255 ^ ((1 << used) - 1))) | value
    return write_wav(params, output), {'required_bytes': size, 'capacity_bytes': available}


def _extract_bytes(frames, width, bits, start, count):
    result = bytearray(count)
    for offset in range(count * 8):
        value = frames[(start + offset // bits) * width]
        result[offset // 8] |= ((value >> (offset % bits)) & 1) << (offset % 8)
    return bytes(result)


def extract(wav_bytes, public_key, bits=1, start=0):
    params, frames = read_wav(wav_bytes)
    available = _capacity(params, bits, start)
    missing = {'authentic': False, 'verdict': Verdict.PAYLOAD_MISSING.value}
    if available < HEADER.size:
        return missing
    header = _extract_bytes(frames, params.sampwidth, bits, start, HEADER.size)
    magic, length = HEADER.unpack(header)
    if magic != MAGIC or length > available - HEADER.size:
        return missing
    packet = _extract_bytes(frames, params.sampwidth, bits, start, HEADER.size + length)
    try:
        envelope = json.loads(packet[HEADER.size:])
        payload = envelope['payload']
        signature = base64.b64decode(envelope['signature'], validate=True)
        if not isinstance(payload, dict) or not verify_payload(public_key, payload, signature):
            return {'authentic': False, 'verdict': Verdict.SIGNATURE_INVALID.value}
        expected = _audio_hash(params, frames, bits, start, len(packet)).hex()
        valid = (payload['hash'] == expected and payload['metadata']['bits'] == bits
                 and payload['metadata']['start'] == start)
        return {'authentic': valid,
                'verdict': Verdict.AUTHENTIC.value if valid else Verdict.TAMPERED.value,
                'payload': payload}
    except (ValueError, KeyError, TypeError, UnicodeError):
        return {'authentic': False, 'verdict': Verdict.CANNOT_VERIFY.value}


def tamper(wav_bytes):
    """Change a PCM bit outside the low byte for a reproducible negative demo."""
    params, frames = read_wav(wav_bytes)
    changed = bytearray(frames)
    changed[-1] ^= 128
    return write_wav(params, changed)
