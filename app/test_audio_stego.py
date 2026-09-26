import io
import math
import wave

import pytest

from app import create_app
from app.audio_stego import capacity, embed, extract, read_wav, tamper, write_wav
from app.crypto_payload import generate_keypair


def cover(width=2, channels=1, samples=16000):
    data = bytearray()
    for i in range(samples):
        value = int(math.sin(2 * math.pi * 440 * i / 16000) * (2 ** (width * 8 - 3)))
        if width == 1:
            value += 128
        data.extend(value.to_bytes(width, 'little', signed=width != 1) * channels)
    output = io.BytesIO()
    with wave.open(output, 'wb') as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(width)
        wav.setframerate(16000)
        wav.writeframes(data)
    return output.getvalue()


@pytest.fixture(scope='module')
def keys():
    return generate_keypair()


@pytest.mark.parametrize('bits', range(1, 9))
@pytest.mark.parametrize('width,channels', [(1, 1), (2, 2), (3, 1), (4, 2)])
def test_round_trip_and_sample_bound(keys, bits, width, channels):
    original = cover(width, channels)
    stego, info = embed(original, 'Hidden message: \u4f60\u597d', keys[0], bits, 37)
    result = extract(stego, keys[1], bits, 37)
    assert result['authentic']
    assert result['payload']['metadata']['message'] == 'Hidden message: \u4f60\u597d'
    before_params, before = read_wav(original)
    after_params, after = read_wav(stego)
    assert before_params == after_params
    assert before[:37 * width] == after[:37 * width]
    for i in range(0, len(before), width):
        a = int.from_bytes(before[i:i + width], 'little', signed=width != 1)
        b = int.from_bytes(after[i:i + width], 'little', signed=width != 1)
        assert abs(a - b) <= (1 << bits) - 1
    assert info['required_bytes'] <= info['capacity_bytes']
    assert not extract(tamper(stego), keys[1], bits, 37)['authentic']


def test_negative_cases(keys):
    original = cover()
    stego, _ = embed(original, 'hello', keys[0])
    assert not extract(original, keys[1])['authentic']
    assert not extract(stego, generate_keypair()[1])['authentic']
    assert not extract(stego, keys[1], start=1)['authentic']
    assert not extract(stego, keys[1], bits=2)['authentic']
    params, frames = read_wav(stego)
    changed = bytearray(frames)
    changed[0] ^= 1  # packet header
    assert not extract(write_wav(params, changed), keys[1])['authentic']
    changed = bytearray(frames)
    changed[2000] ^= 1  # signed payload
    assert not extract(write_wav(params, changed), keys[1])['authentic']
    changed = bytearray(frames)
    changed[-2] ^= 1  # unused LSB must still be hashed
    assert extract(write_wav(params, changed), keys[1])['verdict'] == 'Tampered'
    assert not extract(write_wav(params._replace(framerate=8000), frames), keys[1])['authentic']


def test_capacity_and_invalid_input(keys):
    original = cover(samples=100)
    assert capacity(original, 3, 7) == 93 * 3 // 8
    with pytest.raises(ValueError, match='Capacity exceeded'):
        embed(original, 'hello', keys[0])
    for bits, start in [(0, 0), (9, 0), (1, -1), (1, 100)]:
        with pytest.raises(ValueError):
            capacity(original, bits, start)
    for data in [b'not WAV', original[:-10]]:
        with pytest.raises(ValueError):
            capacity(data)
    with pytest.raises(ValueError, match='Capacity exceeded'):
        embed(cover(), 'x' * 20000, keys[0])


def test_exact_capacity(keys):
    _, info = embed(cover(), 'boundary', keys[0], bits=8)
    exact = cover(samples=info['required_bytes'])
    stego, result = embed(exact, 'boundary', keys[0], bits=8)
    assert result['required_bytes'] == result['capacity_bytes']
    assert extract(stego, keys[1], bits=8)['authentic']
    with pytest.raises(ValueError):
        embed(cover(samples=info['required_bytes'] - 1), 'boundary', keys[0], bits=8)


@pytest.mark.parametrize('bits', range(1, 9))
@pytest.mark.parametrize('width,channels', [(1, 1), (2, 2), (3, 1), (4, 2)])
def test_wrong_start_is_distinct_from_missing(keys, bits, width, channels):
    original = cover(width, channels)
    stego, _ = embed(original, 'Location test', keys[0], bits, 100)
    assert extract(stego, keys[1], bits, 100)['verdict'] == 'Authentic'
    for wrong_start in (0, 1, 101, 16000 * channels - 1):
        result = extract(stego, keys[1], bits, wrong_start)
        assert result == {'authentic': False, 'verdict': 'Wrong Start Location'}
    assert extract(original, keys[1], bits, 1)['verdict'] == 'Payload Missing'


def test_location_detection_requires_trusted_signed_payload(keys):
    stego, _ = embed(cover(), 'Location test', keys[0], 1, 100)
    assert extract(stego, generate_keypair()[1], 1, 1)['verdict'] == 'Payload Missing'
    assert extract(stego, keys[1], 2, 1)['verdict'] == 'Payload Missing'
    params, frames = read_wav(stego)
    changed = bytearray(frames)
    # Preserve the header but zero the opening JSON byte.
    for sample in range(164, 172):
        changed[sample * params.sampwidth] &= 254
    malformed = write_wav(params, changed)
    assert extract(malformed, keys[1], 1, 100)['verdict'] == 'Cannot Verify'
    assert extract(malformed, keys[1], 1, 1)['verdict'] == 'Payload Missing'


@pytest.fixture
def client(monkeypatch, tmp_path):
    # Supply main's required setting only for tests, without writing a .env file.
    monkeypatch.setenv('STEGO_SECRET_KEY', 'audio-integration-test-only')
    app = create_app()
    app.config['TESTING'] = True
    from app import routes
    monkeypatch.setattr(routes, 'UPLOAD_FOLDER', str(tmp_path))
    return app.test_client()


def test_web_workflow(client):
    import base64
    home = client.get('/')
    assert home.status_code == 200
    assert b'Steganographic Integrity Verification' in home.data
    assert b'href="/image"' in home.data
    assert b'href="/audio"' in home.data
    assert client.get('/image').status_code == 200
    assert client.get('/audio').status_code == 200
    result = client.post('/audio/embed', data={
        'audio': (io.BytesIO(cover()), 'cover.wav'), 'message': 'Web demo',
        'bits': '2', 'start': '17'})
    assert result.status_code == 200
    record = result.get_json()
    stego = base64.b64decode(record['audio'])
    def verify(data):
        return client.post('/audio/extract', data={
            'audio': (io.BytesIO(data), 'stego.wav'), 'bits': '2', 'start': '17',
            'public_key': (io.BytesIO(record['public_key'].encode()), 'key.pem')}).get_json()
    assert verify(stego)['authentic']
    wrong_location = client.post('/audio/extract', data={
        'audio': (io.BytesIO(stego), 'stego.wav'), 'bits': '2', 'start': '1',
        'public_key': (io.BytesIO(record['public_key'].encode()), 'key.pem')})
    assert wrong_location.status_code == 200
    assert wrong_location.get_json()['verdict'] == 'Wrong Start Location'
    damaged = client.post('/audio/tamper', data={'audio': (io.BytesIO(stego), 'stego.wav')})
    assert damaged.status_code == 200
    assert not verify(damaged.data)['authentic']
    assert client.post('/audio/embed', data={}).status_code == 400
    assert client.post('/audio/capacity', data={'audio': (io.BytesIO(b'bad'), 'bad.wav')}).status_code == 400


def test_audio_uses_main_persistent_keys(client):
    import base64
    from app import routes
    from cryptography.hazmat.primitives import serialization

    def encode():
        response = client.post('/audio/embed', data={
            'audio': (io.BytesIO(cover()), 'shared-key.wav'), 'message': 'Persistent key'})
        assert response.status_code == 200
        return response.get_json()

    first, second = encode(), encode()
    expected = routes.PUBLIC_KEY.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert first['public_key'] == second['public_key'] == expected
    stego = base64.b64decode(first['audio'])
    response = client.post('/audio/extract', data={
        'audio': (io.BytesIO(stego), 'stego.wav')})
    assert response.get_json()['authentic']
    assert response.get_json()['payload']['media_id'] == 'shared-key.wav'
    wrong_key = generate_keypair()[1].public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    response = client.post('/audio/extract', data={
        'audio': (io.BytesIO(stego), 'stego.wav'),
        'public_key': (io.BytesIO(wrong_key), 'wrong.pem')})
    assert not response.get_json()['authentic']
    response = client.post('/audio/extract', data={
        'audio': (io.BytesIO(stego), 'stego.wav'),
        'public_key': (io.BytesIO(b'bad key'), 'broken.pem')})
    assert response.status_code == 400


def test_main_image_workflow_preserved(client):
    from PIL import Image

    output = io.BytesIO()
    Image.new('RGB', (100, 100), (100, 150, 200)).save(output, format='PNG')
    output.seek(0)
    embedded = client.post('/embed', data={
        'cover_image': (output, 'regression.png'), 'bits_per_channel': '1',
        'message': 'Image regression test'})
    assert embedded.status_code == 200
    stego = client.get('/uploads/stego_regression.png')
    assert stego.status_code == 200
    verified = client.post('/verify', data={
        'stego_image': (io.BytesIO(stego.data), 'received.png'), 'bits_per_channel': '1'})
    assert verified.status_code == 200
    assert b'Authentic' in verified.data


def test_audio_upload_limit_matches_main_proxy(client):
    client.application.config['MAX_CONTENT_LENGTH'] = 100
    response = client.post('/audio/embed', data={
        'audio': (io.BytesIO(cover()), 'large.wav')})
    assert response.status_code == 413
    assert '20 MiB' in response.get_json()['error']



@pytest.mark.parametrize('bits', range(1, 9))
@pytest.mark.parametrize('width,channels', [(1, 1), (2, 2), (3, 1), (4, 2)])
def test_corrupt_payload_preserves_header_and_other_bits(keys, bits, width, channels):
    from app.audio_stego import corrupt_payload, _extract_bytes, HEADER
    stego, _ = embed(cover(width, channels), 'Fresh audio', keys[0], bits, 200)
    damaged = corrupt_payload(stego, bits, 200)
    params, before = read_wav(stego)
    after_params, after = read_wav(damaged)
    assert params == after_params
    assert extract(damaged, keys[1], bits, 200)['verdict'] == 'Cannot Verify'
    assert extract(stego, keys[1], bits, 200)['verdict'] == 'Authentic'
    assert _extract_bytes(before, width, bits, 200, HEADER.size) == _extract_bytes(after, width, bits, 200, HEADER.size)
    allowed = {}
    for offset in range(64, 72):
        index = (200 + offset // bits) * width
        allowed[index] = allowed.get(index, 0) | (1 << (offset % bits))
    for index, (a, b) in enumerate(zip(before, after)):
        assert (a ^ b) & (255 ^ allowed.get(index, 0)) == 0
    with pytest.raises(ValueError):
        corrupt_payload(damaged, bits, 200)


def test_corrupt_payload_web_workflow(client):
    import base64
    response = client.post('/audio/embed', data={
        'audio': (io.BytesIO(cover()), 'fresh.wav'), 'message': 'Fresh message',
        'bits': '3', 'start': '200'})
    stego = base64.b64decode(response.get_json()['audio'])
    response = client.post('/audio/corrupt-payload', data={
        'audio': (io.BytesIO(stego), 'stego.wav'), 'bits': '3', 'start': '200'})
    assert response.status_code == 200
    assert response.mimetype == 'audio/wav'
    assert 'cannot_verify.wav' in response.headers['Content-Disposition']
    verified = client.post('/audio/extract', data={
        'audio': (io.BytesIO(response.data), 'cannot_verify.wav'),
        'bits': '3', 'start': '200'})
    assert verified.get_json()['verdict'] == 'Cannot Verify'
    for audio, bits, start in [(stego, 3, 1), (stego, 1, 200),
                               (cover(), 1, 0), (b'bad', 1, 0),
                               (stego, 9, 200), (stego, 3, -1)]:
        bad = client.post('/audio/corrupt-payload', data={
            'audio': (io.BytesIO(audio), 'test.wav'),
            'bits': str(bits), 'start': str(start)})
        assert bad.status_code == 400
    assert client.post('/audio/corrupt-payload').status_code == 400
    page = client.get('/audio').data
    assert b'cannot-verify-demo' in page
    assert b'Generate demo test files' not in page


def test_generated_cannot_verify_demo(client):
    response = client.post('/audio/generate-cannot-verify-test')
    assert response.status_code == 200
    assert response.mimetype == 'audio/wav'
    assert 'cannot_verify.wav' in response.headers['Content-Disposition']
    params, _ = read_wav(response.data)
    assert params.sampwidth == 2
    result = client.post('/audio/extract', data={
        'audio': (io.BytesIO(response.data), 'cannot_verify.wav'),
        'bits': '1', 'start': '100'})
    assert result.get_json() == {'authentic': False, 'verdict': 'Cannot Verify'}

def test_wrong_public_key_demo(client):
    import base64
    from app import routes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    original_private = routes.PRIVATE_KEY
    original_public = routes.PUBLIC_KEY
    keys = []
    for _ in range(2):
        response = client.post('/audio/generate-wrong-public-key')
        assert response.status_code == 200
        assert 'wrong-public-key.pem' in response.headers['Content-Disposition']
        assert b'PRIVATE KEY' not in response.data
        public = serialization.load_pem_public_key(response.data)
        assert isinstance(public, rsa.RSAPublicKey)
        assert public.public_numbers() != original_public.public_numbers()
        keys.append(response.data)
    assert keys[0] != keys[1]
    assert routes.PRIVATE_KEY is original_private
    assert routes.PUBLIC_KEY is original_public
    record = client.post('/audio/embed', data={
        'audio': (io.BytesIO(cover()), 'fresh.wav'), 'message': 'Wrong key demo',
        'bits': '1', 'start': '100'}).get_json()
    stego = base64.b64decode(record['audio'])
    for key, expected in [(keys[0], 'Signature Invalid'), (None, 'Authentic')]:
        data = {'audio': (io.BytesIO(stego), 'stego.wav'), 'bits': '1', 'start': '100'}
        if key is not None:
            data['public_key'] = (io.BytesIO(key), 'wrong-public-key.pem')
        result = client.post('/audio/extract', data=data)
        assert result.status_code == 200
        assert result.get_json()['verdict'] == expected
    assert b'wrong-key-demo' in client.get('/audio').data
