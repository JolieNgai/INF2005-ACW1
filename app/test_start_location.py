import pytest
from PIL import Image
from app.start_location import (
    CarrierSpec, HEADER_BYTES, WrongStartLocationError, derive_start_location,
    select_start_location, recover_start_location, required_units,
    embed_units, extract_units,
)
from app.image_stego import embed_payload, extract_payload, check_capacity

KEY = bytes(range(32))


@pytest.mark.parametrize("bits", range(1, 9))
@pytest.mark.parametrize("media", ["image", "audio"])
def test_roundtrip_all_depths_and_preserve_upper_bits(bits, media):
    spec = (CarrierSpec.image(40, 40, bits=bits) if media == "image" else
            CarrierSpec.audio(2400, 2, 44100, bits=bits))
    units = ([170] * spec.total_units if media == "image" else
             [-12345, 12345] * (spec.total_units // 2))
    payload = bytes(range(256))
    encoded = embed_units(units, payload, KEY, spec)
    assert extract_units(encoded, KEY, spec) == payload
    assert all((a >> bits) == (b >> bits) for a, b in zip(units, encoded))


def test_selection_recovery_and_fresh_nonce():
    spec = CarrierSpec.image(40, 40)
    start, header = select_start_location(KEY, spec, 20)
    assert recover_start_location(KEY, spec, header) == (start, 20)
    assert spec.header_units <= start < spec.total_units
    assert select_start_location(KEY, spec, 20)[1] != header


@pytest.mark.parametrize("offset", [0, 4, 20, HEADER_BYTES - 1])
def test_header_tampering(offset):
    spec = CarrierSpec.image(40, 40)
    _, header = select_start_location(KEY, spec, 20)
    damaged = bytearray(header)
    damaged[offset] ^= 1
    with pytest.raises(WrongStartLocationError):
        recover_start_location(KEY, spec, bytes(damaged))


def test_wrong_key_bits_metadata_and_explicit_start():
    spec = CarrierSpec.image(40, 40)
    encoded = embed_units([100] * spec.total_units, b"payload", KEY, spec)
    for key, other_spec in [(b"wrong", spec), (KEY, CarrierSpec.image(40, 40, bits=2)),
                            (KEY, CarrierSpec.image(20, 80)),
                            (KEY, CarrierSpec.audio(2400, 2, 44100))]:
        with pytest.raises(WrongStartLocationError):
            extract_units(encoded, key, other_spec)
    with pytest.raises(WrongStartLocationError):
        extract_units(encoded, KEY, spec, start_index=0)


def test_payload_tampering_and_forced_wraparound(monkeypatch):
    spec = CarrierSpec.image(40, 40, bits=3)
    nonce = next(i.to_bytes(16, "big") for i in range(10000)
                 if derive_start_location(KEY, spec, i.to_bytes(16, "big")) > 4700)
    monkeypatch.setattr("app.start_location.secrets.token_bytes", lambda n: nonce)
    start = derive_start_location(KEY, spec, nonce)
    encoded = embed_units([100] * spec.total_units, b"wrap" * 100, KEY, spec)
    assert extract_units(encoded, KEY, spec) == b"wrap" * 100
    encoded[start] ^= 1
    with pytest.raises(WrongStartLocationError):
        extract_units(encoded, KEY, spec)


@pytest.mark.parametrize("bits", range(1, 9))
def test_capacity_boundary_empty_and_missing(bits):
    provisional = CarrierSpec.audio(1000, 1, 8000, bits=bits)
    count = required_units(10, provisional)
    spec = CarrierSpec.audio(count, 1, 8000, bits=bits)
    assert extract_units(embed_units([0] * count, b"x" * 10, KEY, spec), KEY, spec) == b"x" * 10
    with pytest.raises(ValueError, match="capacity"):
        embed_units([0] * count, b"x" * 11, KEY, spec)
    assert extract_units(embed_units([0] * count, b"", KEY, spec), KEY, spec) == b""
    with pytest.raises(WrongStartLocationError):
        extract_units([0] * count, KEY, spec)


@pytest.mark.parametrize("bits", range(1, 9))
def test_png_integration(tmp_path, bits):
    cover, output = tmp_path / "cover.png", tmp_path / "stego.png"
    Image.new("RGB", (60, 60), (170, 85, 127)).save(cover)
    payload = bytes(range(256))
    assert check_capacity(60, 60, 3, len(payload), bits)[0]
    embed_payload(cover, output, payload, KEY, bits)
    assert extract_payload(output, KEY, bits) == payload


def test_verification_verdict(tmp_path):
    from app.crypto_payload import run_verification
    cover = tmp_path / "cover.png"
    Image.new("RGB", (60, 60)).save(cover)
    verdict, payload = run_verification(cover, KEY, 1, None, None, extract_payload)
    assert (verdict, payload) == ("Wrong Start Location", None)


@pytest.mark.parametrize("bits", [0, -1, 9])
def test_invalid_bits(bits):
    with pytest.raises(ValueError):
        CarrierSpec.image(40, 40, bits=bits)


@pytest.mark.parametrize("width", [8, 16, 24, 32])
def test_pcm_sample_widths(width):
    spec = CarrierSpec.audio(2000, 1, 48000, sample_width=width, bits=3)
    values = [128] * 2000 if width == 8 else [-(1 << (width - 1)), (1 << (width - 1)) - 1] * 1000
    encoded = embed_units(values, b"audio", KEY, spec)
    assert extract_units(encoded, KEY, spec) == b"audio"
    assert all(a >> 3 == b >> 3 for a, b in zip(values, encoded))


def test_signed_image_still_authentic_and_cover_tampering_detected(tmp_path):
    import json
    from app.crypto_payload import (
        generate_keypair, stable_hash, build_payload, sign_payload, run_verification,
    )
    cover, output = tmp_path / "cover.png", tmp_path / "stego.png"
    img = Image.new("RGB", (100, 100), (128, 64, 32))
    img.save(cover)
    private, public = generate_keypair()
    payload = build_payload("test", stable_hash(img.tobytes(), 3), {})
    frame = json.dumps({"payload": payload, "signature": sign_payload(private, payload).hex()}).encode()

    def unpack(data):
        package = json.loads(data)
        return package["payload"], bytes.fromhex(package["signature"])

    embed_payload(cover, output, frame, KEY, 3)
    assert run_verification(output, KEY, 3, public, unpack, extract_payload)[0] == "Authentic"
    with Image.open(output) as saved:
        modified = saved.copy()
    r, g, b = modified.getpixel((0, 0))
    modified.putpixel((0, 0), (r ^ 128, g, b))
    modified.save(output)
    assert run_verification(output, KEY, 3, public, unpack, extract_payload)[0] == "Tampered"
