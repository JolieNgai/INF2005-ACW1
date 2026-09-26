"""Run `python -m app.audio_demo` to create reproducible listening/test assets."""
import io
import json
import math
from pathlib import Path
import struct
import wave

from cryptography.hazmat.primitives import serialization

from .audio_stego import embed, extract, tamper
from .crypto_payload import generate_keypair


def demo_cover():
    output = io.BytesIO()
    with wave.open(output, 'wb') as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(44100)
        wav.writeframes(b''.join(struct.pack('<h', int(8000 * math.sin(2 * math.pi * 440 * i / 44100)))
                                 for i in range(44100 * 3)))
    return output.getvalue()


def main():
    directory = Path('examples/audio')
    directory.mkdir(parents=True, exist_ok=True)
    cover = demo_cover()
    private, public = generate_keypair()
    protected, sizes = embed(cover, 'Explain how steganography can be used to embed hidden verification data.',
                              private, bits=1, start=100)
    damaged = tamper(protected)
    for name, data in [('cover.wav', cover), ('stego.wav', protected), ('tampered.wav', damaged)]:
        (directory / name).write_bytes(data)
    (directory / 'public-key.pem').write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    evidence = {'bits': 1, 'start': 100, **sizes,
                'positive': extract(protected, public, 1, 100),
                'negative': extract(damaged, public, 1, 100)}
    (directory / 'verification.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
