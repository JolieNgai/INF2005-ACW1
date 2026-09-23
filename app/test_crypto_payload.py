from app.crypto_payload import (
    generate_keypair,
    hash_cover_object,
    build_payload,
    sign_payload,
    verify_payload,
)


def test_verify_pass():
    priv, pub = generate_keypair()
    h = hash_cover_object(b"test data")
    payload = build_payload("IMG001", h, {"x": 1})
    sig = sign_payload(priv, payload)
    assert verify_payload(pub, payload, sig) is True


def test_verify_fail_on_tamper():
    priv, pub = generate_keypair()
    h = hash_cover_object(b"test data")
    payload = build_payload("IMG001", h, {"x": 1})
    sig = sign_payload(priv, payload)
    payload["metadata"]["x"] = 999
    assert verify_payload(pub, payload, sig) is False


def test_verify_fail_wrong_key():
    priv, pub = generate_keypair()
    _, wrong_pub = generate_keypair()
    h = hash_cover_object(b"test data")
    payload = build_payload("IMG001", h, {"x": 1})
    sig = sign_payload(priv, payload)
    assert verify_payload(wrong_pub, payload, sig) is False


def test_verify_fail_tampered_hash_field():
    priv, pub = generate_keypair()
    h = hash_cover_object(b"test data")
    payload = build_payload("IMG001", h, {"x": 1})
    sig = sign_payload(priv, payload)
    payload["hash"] = "00" * 32  # simulate swapped/corrupted cover object
    assert verify_payload(pub, payload, sig) is False

def test_verify_fail_corrupted_signature():
    priv, pub = generate_keypair()
    h = hash_cover_object(b"test data")
    payload = build_payload("IMG001", h, {"x": 1})
    sig = sign_payload(priv, payload)
    corrupted_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    assert verify_payload(pub, payload, corrupted_sig) is False


def test_verify_fail_missing_payload():
    priv, pub = generate_keypair()
    h = hash_cover_object(b"test data")
    payload = build_payload("IMG001", h, {"x": 1})
    sig = sign_payload(priv, payload)
    assert verify_payload(pub, {}, sig) is False


def test_verify_pass_varying_payload_sizes():
    priv, pub = generate_keypair()
    h = hash_cover_object(b"test data")

    short_payload = build_payload("IMG001", h, {"note": "short message"})
    short_sig = sign_payload(priv, short_payload)
    assert verify_payload(pub, short_payload, short_sig) is True

    large_payload = build_payload("IMG001", h, {"note": "a " * 500})
    large_sig = sign_payload(priv, large_payload)
    assert verify_payload(pub, large_payload, large_sig) is True