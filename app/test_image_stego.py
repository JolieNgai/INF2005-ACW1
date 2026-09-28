"""
Automated tests for capacity checking, payload size variation, and
selectable LSB bit-depths (1-8), matching the assignment's required
test categories.

Run with:  pytest app\test_image_stego.py -v
"""
import io
import json
import pytest
from PIL import Image

from app.image_stego import check_capacity, embed_payload, extract_payload
from app.crypto_payload import (
    generate_keypair, stable_hash, build_payload,
    sign_payload, verify_payload, run_verification,
)

SECRET_KEY_PHRASE = "test-secret-key-for-pytest"

LEARNING_OBJECTIVE = (
    "Identify and justify innovation incorporated into the team's "
    "design or implementation."
)

PROJECT_OVERVIEW = (
    "This undergraduate project requires student teams to design, implement "
    "and demonstrate a GUI-based LSB Replacement steganography program "
    "(window-based or web-based) that protects and verifies both image and "
    "audio cover objects using steganography, hashing and digital signatures. "
    "The project focuses on practical cybersecurity concepts: hiding a "
    "verification payload inside an image and an audio file, signing relevant "
    "verification data, extracting the hidden payload, checking the digital "
    "signature, and demonstrating positive and negative verification cases. "
    "Video as a cover object is not required for the main assignment, but "
    "may be attempted as an optional challenge."
)

CUSTOM_PAYLOAD = "P6-7 custom verification token :: order-id=88213, checksum=A93F"


def pack_payload(payload: dict, signature: bytes) -> bytes:
    package = {"payload": payload, "signature": signature.hex()}
    return json.dumps(package, sort_keys=True).encode()


def unpack_payload(data: bytes) -> tuple[dict, bytes]:
    package = json.loads(data.decode())
    return package["payload"], bytes.fromhex(package["signature"])


def make_cover(path, size=(300, 300)):
    """Cover image with varied pixel content (not flat), so it behaves
    like a realistic photo rather than a degenerate solid-color image."""
    img = Image.new("RGB", size)
    px = img.load()
    w, h = size
    for x in range(w):
        for y in range(h):
            px[x, y] = ((x * 3) % 256, (y * 5) % 256, (x + y) % 256)
    img.save(path, "PNG")
    return path


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


def do_embed(cover_path, stego_path, message, bits, private_key):
    img = Image.open(cover_path).convert("RGB")
    width, height = img.size
    cover_hash = stable_hash(img.tobytes(), bits)
    payload = build_payload(
        media_id="test.png",
        cover_hash=cover_hash,
        metadata={"team": "P6-7", "bits_per_channel": bits, "message": message},
    )
    signature = sign_payload(private_key, payload)
    data_to_embed = pack_payload(payload, signature)

    fits, msg = check_capacity(width, height, 3, len(data_to_embed), bits)
    if fits:
        embed_payload(cover_path, stego_path, data_to_embed, SECRET_KEY_PHRASE, bits_per_channel=bits)
    return fits, msg, payload


def do_verify(stego_path, bits, public_key):
    return run_verification(
        stego_path=stego_path,
        key=SECRET_KEY_PHRASE,
        bits=bits,
        public_key=public_key,
        unpack_payload_fn=unpack_payload,
        extract_payload_fn=extract_payload,
    )

# 1. Capacity check: payload larger than cover object
class TestCapacityCheck:

    def test_payload_too_large_for_tiny_cover_rejected(self, tmp_path, keypair):
        """A 20x20 cover at 1 bit/channel has far too little room for the
        full Project Overview paragraph — must be rejected, not truncated
        or silently corrupted."""
        priv, _ = keypair
        cover_path = make_cover(tmp_path / "tiny_cover.png", size=(20, 20))
        stego_path = tmp_path / "tiny_stego.png"

        fits, msg, _ = do_embed(cover_path, stego_path, PROJECT_OVERVIEW, bits=1, private_key=priv)

        assert fits is False
        assert "too large" in msg.lower() or "capacity" in msg.lower() or "channel" in msg.lower()
        assert not stego_path.exists()  # nothing should have been written

    def test_same_tiny_cover_fits_at_higher_bit_depth(self, tmp_path, keypair):
        """Same cover, same message, but 8 bits/channel gives 8x the raw
        capacity — should now succeed. Confirms the check is dynamic,
        not a hardcoded rejection."""
        priv, pub = keypair
        cover_path = make_cover(tmp_path / "tiny_cover2.png", size=(30, 30))
        stego_path = tmp_path / "tiny_stego2.png"

        fits, msg, payload = do_embed(cover_path, stego_path, PROJECT_OVERVIEW, bits=8, private_key=priv)

        assert fits is True
        assert stego_path.exists()
        verdict, extracted = do_verify(str(stego_path), 8, pub)
        assert verdict == "Authentic"
        assert extracted["metadata"]["message"] == PROJECT_OVERVIEW

    def test_boundary_one_byte_over_limit_rejected_then_fits(self, tmp_path, keypair):
        priv, pub = keypair
        cover_path = make_cover(tmp_path / "boundary_cover.png", size=(100, 100))
        bits = 1

        lo, hi = 0, 5000
        largest_that_fits = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            fits, _, _ = do_embed(cover_path, tmp_path / f"probe_{mid}.png", "A" * mid, bits, priv)
            if fits:
                largest_that_fits = mid
                lo = mid + 1
            else:
                hi = mid - 1

        assert largest_that_fits > 0, "sanity: cover should fit *something*"

        fits, msg, _ = do_embed(cover_path, tmp_path / "over.png", "A" * (largest_that_fits + 1), bits, priv)
        assert fits is False, f"expected rejection 1 byte over the limit, got: {msg}"

        fits, msg, payload = do_embed(cover_path, tmp_path / "exact.png", "A" * largest_that_fits, bits, priv)
        assert fits is True, f"expected success exactly at the limit, got: {msg}"
        verdict, extracted = do_verify(str(tmp_path / "exact.png"), bits, pub)
        assert verdict == "Authentic"


# 3. Various payload sizes: short / large / custom

class TestPayloadSizes:

    @pytest.mark.parametrize("label,message", [
        ("short_learning_objective", LEARNING_OBJECTIVE),
        ("large_project_overview", PROJECT_OVERVIEW),
        ("custom_payload", CUSTOM_PAYLOAD),
    ])
    def test_embed_then_verify_roundtrip(self, tmp_path, keypair, label, message):
        priv, pub = keypair
        cover_path = make_cover(tmp_path / f"cover_{label}.png")
        stego_path = tmp_path / f"stego_{label}.png"
        bits = 2

        fits, msg, original_payload = do_embed(cover_path, stego_path, message, bits, priv)
        assert fits, f"{label} unexpectedly did not fit: {msg}"

        verdict, extracted = do_verify(str(stego_path), bits, pub)
        assert verdict == "Authentic", f"{label} failed verification: {verdict}"
        assert extracted["metadata"]["message"] == message
        assert extracted["hash"] == original_payload["hash"]

    def test_larger_message_uses_more_capacity_than_shorter(self, tmp_path, keypair):
        """Sanity check that capacity usage actually scales with message
        length, rather than being some fixed/ignored value."""
        priv, _ = keypair
        bits = 2
        cover_short = make_cover(tmp_path / "cshort.png")
        cover_large = make_cover(tmp_path / "clarge.png")

        _, msg_short, _ = do_embed(cover_short, tmp_path / "sshort.png", LEARNING_OBJECTIVE, bits, priv)
        _, msg_large, _ = do_embed(cover_large, tmp_path / "slarge.png", PROJECT_OVERVIEW, bits, priv)

        def channels_used(msg):
            return int(msg.split(":")[1].split("/")[0].strip())

        assert channels_used(msg_large) > channels_used(msg_short)


# 4. Selectable LSBs 1 through 8
class TestSelectableBitDepths:

    @pytest.mark.parametrize("bits", range(1, 9))
    def test_roundtrip_at_each_bit_depth(self, tmp_path, keypair, bits):
        priv, pub = keypair
        cover_path = make_cover(tmp_path / f"cover_bits{bits}.png")
        stego_path = tmp_path / f"stego_bits{bits}.png"

        fits, msg, original_payload = do_embed(cover_path, stego_path, LEARNING_OBJECTIVE, bits, priv)
        assert fits, f"bits={bits} unexpectedly didn't fit: {msg}"

        verdict, extracted = do_verify(str(stego_path), bits, pub)
        assert verdict == "Authentic", f"bits={bits} gave verdict {verdict}"
        assert extracted["metadata"]["message"] == LEARNING_OBJECTIVE

    def test_capacity_channels_needed_decreases_as_bits_increase(self, tmp_path, keypair):
        """Same payload, same cover: higher bit-depth should need fewer
        channel-writes since more bits are packed per channel."""
        priv, _ = keypair
        cover_path = make_cover(tmp_path / "cover_scaling.png")

        def channels_used(msg):
            return int(msg.split(":")[1].split("/")[0].strip())

        usage = {}
        for bits in range(1, 9):
            fits, msg, _ = do_embed(cover_path, tmp_path / f"s{bits}.png", PROJECT_OVERVIEW, bits, priv)
            assert fits
            usage[bits] = channels_used(msg)

        for b in range(1, 8):
            assert usage[b] >= usage[b + 1], (
                f"expected channels used to shrink or stay equal as bits "
                f"increase, but bits={b} used {usage[b]} and bits={b+1} used {usage[b+1]}"
            )

    def test_mismatched_bit_depth_between_embed_and_verify_is_rejected(self, tmp_path, keypair):
        """Embedding at one bit-depth, then verifying at another, must
        fail cleanly (Cannot Verify / Payload Missing / Signature Invalid)
        rather than hang or return a false Authentic. Regression test for
        the WORKER TIMEOUT bug caused by an unbounded payload_length read."""
        priv, pub = keypair
        cover_path = make_cover(tmp_path / "cover_mismatch.png")
        stego_path = tmp_path / "stego_mismatch.png"

        fits, _, _ = do_embed(cover_path, stego_path, LEARNING_OBJECTIVE, bits=3, private_key=priv)
        assert fits

        verdict, _ = do_verify(str(stego_path), bits=5, public_key=pub)
        assert verdict in (
            "Cannot Verify", "Payload Missing", "Signature Invalid", "Wrong Start Location"
            ), f"expected a rejection verdict for mismatched bit-depth, got {verdict}"
        