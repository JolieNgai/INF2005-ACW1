"""Automated attacks against crypto, image and audio steganography modules."""

from __future__ import annotations

import base64
import copy
import io
import json
import math
import wave
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image

from app import audio_stego
from app.crypto_payload import (
    build_payload,
    generate_keypair,
    hash_cover_object,
    run_verification,
    sign_payload,
    stable_hash,
    verify_payload,
)
from app.image_stego import check_capacity, embed_payload, extract_payload
from app.verdict import Verdict

from app.start_location import (
    CarrierSpec,
    WrongStartLocationError,
    extract_units,
)


SINGAPORE_TIMEZONE = timezone(timedelta(hours=8), name="SGT")


@dataclass(frozen=True)
class AttackResult:
    """One result produced by the attack simulation."""

    test_id: str
    attack: str
    expected_verification: bool
    actual_verification: bool
    passed: bool
    attack_detected: bool | None
    evidence: str


def _result(
    test_id: str,
    attack: str,
    expected_verification: bool,
    actual_verification: bool,
    evidence: str,
    *,
    is_attack: bool = True,
) -> AttackResult:
    return AttackResult(
        test_id=test_id,
        attack=attack,
        expected_verification=expected_verification,
        actual_verification=actual_verification,
        passed=actual_verification is expected_verification,
        attack_detected=(not actual_verification) if is_attack else None,
        evidence=evidence,
    )

def _verdict_text(verdict: Verdict | str) -> str:
    """Return a printable verdict for enums and plain strings."""

    return verdict.value if isinstance(verdict, Verdict) else str(verdict)

def run_crypto_attack_sweep() -> list[AttackResult]:
    """Run attacks that only depend on the standalone crypto module."""

    private_key, public_key = generate_keypair()
    _, wrong_public_key = generate_keypair()

    cover_hash = hash_cover_object(b"original cover object")
    payload = build_payload("IMG001", cover_hash, {"team": "P6-7"})
    signature = sign_payload(private_key, payload)
    results: list[AttackResult] = []

    # Positive baseline: verify the unchanged payload with its matching key.
    verified = verify_payload(public_key, payload, signature)
    results.append(
        _result(
            "CRYPTO-POS-01",
            "baseline_valid_payload",
            True,
            verified,
            "Original payload and signature verified using the correct public key.",
            is_attack=False,
        )
    )

    # Payload corruption: change signed metadata while retaining its signature.
    tampered_payload = copy.deepcopy(payload)
    tampered_payload["metadata"]["team"] = "ATTACKER"
    verified = verify_payload(public_key, tampered_payload, signature)
    results.append(
        _result(
            "CRYPTO-NEG-01",
            "payload_corruption",
            False,
            verified,
            "Changed metadata after signing while keeping the original signature.",
        )
    )

    # Wrong key: verify the signature using an unrelated public key.
    verified = verify_payload(wrong_public_key, payload, signature)
    results.append(
        _result(
            "CRYPTO-NEG-02",
            "wrong_public_key",
            False,
            verified,
            "Verified the original signature using an unrelated RSA public key.",
        )
    )

    # Signature corruption: flip bits in the signature before verification.
    corrupted_signature = bytearray(signature)
    corrupted_signature[-1] ^= 0xFF
    verified = verify_payload(public_key, payload, bytes(corrupted_signature))
    results.append(
        _result(
            "CRYPTO-NEG-03",
            "signature_corruption",
            False,
            verified,
            "Flipped every bit in the final signature byte.",
        )
    )

    return results


def _pack_payload(payload: dict, signature: bytes) -> bytes:
    """Use the same package format as app/routes.py."""

    package = {"payload": payload, "signature": signature.hex()}
    return json.dumps(package, sort_keys=True).encode()


def _unpack_payload(data: bytes) -> tuple[dict, bytes]:
    """Use the same package format as app/routes.py."""

    package = json.loads(data.decode())
    return package["payload"], bytes.fromhex(package["signature"])


def _make_cover(path: Path, colour: tuple[int, int, int]) -> None:
    """Generate a reproducible PNG cover without needing sample files."""

    Image.new("RGB", (96, 96), colour).save(path, "PNG")


def _signed_image_payload(
    cover_path: Path,
    media_id: str,
    private_key,
    bits: int,
) -> tuple[dict, bytes]:
    image = Image.open(cover_path).convert("RGB")
    payload = build_payload(
        media_id,
        stable_hash(image.tobytes(), bits),
        {"team": "P6-7", "bits_per_channel": bits},
    )
    return payload, sign_payload(private_key, payload)


def _verify_image(
    image_path: Path,
    start_key: str,
    bits: int,
    public_key,
) -> tuple[Verdict | str, dict | None]:
    return run_verification(
        stego_path=image_path,
        key=start_key,
        bits=bits,
        public_key=public_key,
        unpack_payload_fn=_unpack_payload,
        extract_payload_fn=extract_payload,
    )


def run_image_attack_sweep() -> list[AttackResult]:
    """Run attacks against the complete image embedding and verification flow."""

    private_key, public_key = generate_keypair()
    _, wrong_public_key = generate_keypair()
    correct_start_key = "image-attack-simulation-key"
    wrong_start_key = "wrong-start-location-key"
    bits = 1
    results: list[AttackResult] = []

    with TemporaryDirectory() as temporary_directory:
        workdir = Path(temporary_directory)
        cover_path = workdir / "cover.png"
        baseline_path = workdir / "baseline_stego.png"
        _make_cover(cover_path, (120, 160, 200))

        payload, signature = _signed_image_payload(
            cover_path, "IMG001", private_key, bits
        )
        embed_payload(
            str(cover_path),
            str(baseline_path),
            _pack_payload(payload, signature),
            correct_start_key,
            bits,
        )

        # Positive baseline: verify an unchanged signed stego image.
        verdict, _ = _verify_image(
            baseline_path, correct_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-POS-01",
                "baseline_valid_stego_image",
                True,
                verdict == Verdict.AUTHENTIC,
                f"Valid stego image verification; verdict={_verdict_text(verdict)}.",
                is_attack=False,
            )
        )

        # Payload corruption: change metadata but retain its original signature.
        corrupted_payload = copy.deepcopy(payload)
        corrupted_payload["metadata"]["team"] = "ATTACKER"
        corrupted_payload_path = workdir / "corrupted_payload.png"
        embed_payload(
            str(cover_path),
            str(corrupted_payload_path),
            _pack_payload(corrupted_payload, signature),
            correct_start_key,
            bits,
        )
        verdict, _ = _verify_image(
            corrupted_payload_path, correct_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-01",
                "embedded_payload_corruption",
                False,
                verdict == Verdict.AUTHENTIC,
                f"Changed signed metadata while retaining its signature; verdict={_verdict_text(verdict)}.",
            )
        )

        # Wrong key: verify the image using an unrelated RSA public key.
        verdict, _ = _verify_image(
            baseline_path, correct_start_key, bits, wrong_public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-02",
                "wrong_public_key",
                False,
                verdict == Verdict.AUTHENTIC,
                f"Used an unrelated RSA public key; verdict={_verdict_text(verdict)}.",
            )
        )

        # Signature corruption: damage the signature embedded in the image.
        damaged_signature = bytearray(signature)
        damaged_signature[-1] ^= 0xFF
        damaged_signature_path = workdir / "corrupted_signature.png"
        embed_payload(
            str(cover_path),
            str(damaged_signature_path),
            _pack_payload(payload, bytes(damaged_signature)),
            correct_start_key,
            bits,
        )
        verdict, _ = _verify_image(
            damaged_signature_path, correct_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-03",
                "embedded_signature_corruption",
                False,  # Expected authentication result
                verdict == Verdict.AUTHENTIC,  # Actual result evaluated at runtime
                f"Corrupted the embedded signature; verdict={_verdict_text(verdict)}.",
            )
        )

        # Wrong start secret: derive the extraction location with another key.
        verdict, _ = _verify_image(
            baseline_path, wrong_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-04",
                "wrong_start_location",
                False,
                verdict == Verdict.AUTHENTIC,
                f"Derived extraction position using the wrong key; verdict={_verdict_text(verdict)}.",
            )
        )

        # Pixel tampering: change a non-LSB bit after embedding.
        tampered_path = workdir / "tampered_pixels.png"
        stego_image = Image.open(baseline_path).convert("RGB")
        pixels = bytearray(stego_image.tobytes())
        pixels[0] ^= 0x80  # Change a non-LSB bit, preserving embedded LSB data.
        Image.frombytes("RGB", stego_image.size, bytes(pixels)).save(
            tampered_path, "PNG"
        )
        verdict, _ = _verify_image(
            tampered_path, correct_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-05",
                "cover_pixel_tampering",
                False,
                verdict == Verdict.AUTHENTIC,
                f"Changed a non-LSB cover-image bit; verdict={_verdict_text(verdict)}.",
            )
        )

        # Oversized payload: find the actual maximum capacity using the
        # current authenticated-framing implementation.
        with Image.open(cover_path) as cover_image:
            width, height = cover_image.size

        channels = 3  # embed_payload() converts the image to RGB.

        # Binary search for the largest payload accepted by check_capacity().
        lowest = 0
        highest = width * height * channels

        while lowest < highest:
            candidate = (lowest + highest + 1) // 2

            fits, _ = check_capacity(
                width,
                height,
                channels,
                candidate,
                bits,
            )

            if fits:
                lowest = candidate
            else:
                highest = candidate - 1

        maximum_payload_bytes = lowest
        oversized_payload = b"X" * (maximum_payload_bytes + 1)

        # Confirm that the capacity checker rejects one byte over the limit.
        fits, capacity_message = check_capacity(
            width,
            height,
            channels,
            len(oversized_payload),
            bits,
        )

        oversized_rejected = False
        rejection_message = "No capacity error was raised."

        try:
            embed_payload(
                str(cover_path),
                str(workdir / "oversized.png"),
                oversized_payload,
                correct_start_key,
                bits,
            )
        except ValueError as error:
            oversized_rejected = True
            rejection_message = str(error)

        results.append(
            _result(
                "IMAGE-NEG-06",
                "oversized_payload",
                False,
                fits or not oversized_rejected,
                (
                    f"Maximum accepted payload={maximum_payload_bytes} bytes; "
                    f"attempted={len(oversized_payload)} bytes; "
                    f"capacity_check_fits={fits}; "
                    f"capacity_check={capacity_message}; "
                    f"embed_result={rejection_message}"
                ),
            )
        )

        # Read the valid stego image as RGB channel units. This uses the same
        # image dimensions and LSB setting that were used during embedding.
        with Image.open(baseline_path) as source:
            baseline_image = source.convert("RGB")

        carrier_spec = CarrierSpec.image(
            *baseline_image.size,
            bits=bits,
        )
        stego_units = baseline_image.tobytes()

        # Force extraction to use index zero. Index zero belongs to the fixed
        # bootstrap region, so it cannot be the derived payload start location.
        wrong_index_accepted = False
        wrong_index_evidence = (
            "No WrongStartLocationError was raised for the supplied index."
        )

        try:
            extract_units(
                stego_units,
                correct_start_key,
                carrier_spec,
                start_index=0,
            )
            wrong_index_accepted = True
        except WrongStartLocationError as error:
            wrong_index_evidence = str(error)

        results.append(
            _result(
                "IMAGE-NEG-07",
                "explicit_wrong_start_index",
                False,
                wrong_index_accepted,
                (
                    "Forced extraction at index 0 instead of the keyed derived "
                    f"payload location; {wrong_index_evidence}"
                ),
            )
        )

        # Flip one LSB inside the fixed bootstrap header. The bootstrap contains
        # the nonce, payload length and header HMAC, so this modification should
        # be rejected before the payload is trusted.
        damaged_bootstrap_units = bytearray(stego_units)
        damaged_bootstrap_units[0] ^= 0x01

        damaged_bootstrap_path = workdir / "damaged_bootstrap.png"
        Image.frombytes(
            "RGB",
            baseline_image.size,
            bytes(damaged_bootstrap_units),
        ).save(damaged_bootstrap_path, "PNG")

        damaged_bootstrap_accepted = False
        bootstrap_evidence = (
            "No WrongStartLocationError was raised after bootstrap tampering."
        )

        try:
            extract_payload(
                str(damaged_bootstrap_path),
                correct_start_key,
                bits,
            )
            damaged_bootstrap_accepted = True
        except WrongStartLocationError as error:
            bootstrap_evidence = str(error)

        results.append(
            _result(
                "IMAGE-NEG-08",
                "bootstrap_header_tampering",
                False,
                damaged_bootstrap_accepted,
                (
                    "Flipped one embedded LSB in the authenticated bootstrap "
                    f"header; {bootstrap_evidence}"
                ),
            )
        )

    return results


def _make_audio_cover(
    samples: int = 16000,
    sample_width: int = 2,
    channels: int = 1,
) -> bytes:
    """Generate a deterministic PCM WAV cover without external sample files."""

    frames = bytearray()
    for index in range(samples):
        value = int(
            math.sin(2 * math.pi * 440 * index / 16000)
            * (2 ** (sample_width * 8 - 3))
        )
        if sample_width == 1:
            value += 128
        sample = value.to_bytes(
            sample_width, "little", signed=sample_width != 1
        )
        frames.extend(sample * channels)

    output = io.BytesIO()
    with wave.open(output, "wb") as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(sample_width)
        wav.setframerate(16000)
        wav.writeframes(frames)
    return output.getvalue()


def _read_audio_envelope(
    stego_bytes: bytes,
    bits: int,
    start: int,
) -> dict:
    """Read the embedded JSON envelope for controlled attack mutation."""

    params, frames = audio_stego.read_wav(stego_bytes)
    header = audio_stego._extract_bytes(
        frames, params.sampwidth, bits, start, audio_stego.HEADER.size
    )
    magic, body_length = audio_stego.HEADER.unpack(header)
    if magic != audio_stego.MAGIC:
        raise ValueError("Audio attack fixture does not contain a valid packet.")
    packet = audio_stego._extract_bytes(
        frames,
        params.sampwidth,
        bits,
        start,
        audio_stego.HEADER.size + body_length,
    )
    return json.loads(packet[audio_stego.HEADER.size:])


def _replace_audio_packet(
    stego_bytes: bytes,
    payload: dict,
    signature: bytes,
    bits: int,
    start: int,
) -> bytes:
    """Replace a packet while retaining the WAV parameters and PCM cover."""

    packet = audio_stego._packet(payload, signature)
    params, frames = audio_stego.read_wav(stego_bytes)
    if len(packet) > audio_stego.capacity(stego_bytes, bits, start):
        raise ValueError("Replacement audio packet exceeds cover capacity.")

    output = bytearray(frames)
    for offset in range(0, len(packet) * 8, bits):
        used = min(bits, len(packet) * 8 - offset)
        value = sum(
            (
                (packet[(offset + bit) // 8] >> ((offset + bit) % 8))
                & 1
            )
            << bit
            for bit in range(used)
        )
        frame_index = (start + offset // bits) * params.sampwidth
        output[frame_index] = (
            output[frame_index] & (255 ^ ((1 << used) - 1))
        ) | value
    return audio_stego.write_wav(params, output)


def run_audio_attack_sweep() -> list[AttackResult]:
    """Run attacks against the complete PCM WAV embedding workflow."""

    private_key, public_key = generate_keypair()
    _, wrong_public_key = generate_keypair()
    bits = 1
    start = 37
    results: list[AttackResult] = []

    # Positive baseline: embed and verify an unchanged signed WAV payload.
    cover = _make_audio_cover()
    stego, _ = audio_stego.embed(
        cover,
        "ORIGINAL",
        private_key,
        bits=bits,
        start=start,
        media_id="AUDIO001",
    )

    verification = audio_stego.extract(
        stego, public_key, bits=bits, start=start
    )
    results.append(
        _result(
            "AUDIO-POS-01",
            "baseline_valid_stego_audio",
            True,
            verification["authentic"],
            f"Valid signed payload extracted from WAV; verdict={verification['verdict']}.",
            is_attack=False,
        )
    )

    envelope = _read_audio_envelope(stego, bits, start)
    original_signature = base64.b64decode(
        envelope["signature"], validate=True
    )

    # Payload corruption: modify the message but retain its original signature.
    corrupted_payload = copy.deepcopy(envelope["payload"])
    corrupted_payload["metadata"]["message"] = "ATTACKER"
    corrupted_payload_audio = _replace_audio_packet(
        stego,
        corrupted_payload,
        original_signature,
        bits,
        start,
    )
    verification = audio_stego.extract(
        corrupted_payload_audio, public_key, bits=bits, start=start
    )
    results.append(
        _result(
            "AUDIO-NEG-01",
            "embedded_payload_corruption",
            False,
            verification["authentic"],
            f"Changed the signed audio message while retaining its signature; verdict={verification['verdict']}.",
        )
    )

    # Wrong key: verify the audio using an unrelated RSA public key.
    verification = audio_stego.extract(
        stego, wrong_public_key, bits=bits, start=start
    )
    results.append(
        _result(
            "AUDIO-NEG-02",
            "wrong_public_key",
            False,
            verification["authentic"],
            f"Used an unrelated RSA public key; verdict={verification['verdict']}.",
        )
    )

    # Signature corruption: damage the RSA signature embedded in the WAV.
    damaged_signature = bytearray(original_signature)
    damaged_signature[-1] ^= 0xFF
    corrupted_signature_audio = _replace_audio_packet(
        stego,
        envelope["payload"],
        bytes(damaged_signature),
        bits,
        start,
    )
    
    verification = audio_stego.extract(
        corrupted_signature_audio, public_key, bits=bits, start=start
    )
    results.append(
        _result(
            "AUDIO-NEG-03",
            "embedded_signature_corruption",
            False,
            verification["authentic"],
            f"Corrupted the embedded RSA signature; verdict={verification['verdict']}.",
        )
    )

    # Wrong start location: extract one sample after the correct position.
    verification = audio_stego.extract(
        stego, public_key, bits=bits, start=start + 1
    )
    results.append(
        _result(
            "AUDIO-NEG-04",
            "wrong_start_location",
            False,
            verification["authentic"],
            f"Extracted one sample after the correct start; verdict={verification['verdict']}.",
        )
    )

    # Audio tampering: modify a PCM bit outside the embedded packet.
    tampered_audio = audio_stego.tamper(stego)
    verification = audio_stego.extract(
        tampered_audio, public_key, bits=bits, start=start
    )
    results.append(
        _result(
            "AUDIO-NEG-05",
            "audio_sample_tampering",
            False,
            verification["authentic"],
            f"Changed a PCM bit outside the embedded payload; verdict={verification['verdict']}.",
        )
    )

    # Oversized payload: confirm an undersized WAV rejects the packet.
    oversized_rejected = False
    rejection_message = "No capacity error was raised."
    try:
        audio_stego.embed(
            _make_audio_cover(samples=100),
            "OVERSIZED",
            private_key,
            bits=bits,
            start=0,
            media_id="AUDIO-SMALL",
        )
    except ValueError as error:
        oversized_rejected = True
        rejection_message = str(error)

    results.append(
        _result(
            "AUDIO-NEG-06",
            "oversized_payload",
            False,
            not oversized_rejected,
            f"Attempted to embed a signed packet in an undersized WAV; {rejection_message}",
        )
    )

    return results


def write_evidence(
    results: list[AttackResult],
    output_path: str | Path,
    generated_at: datetime | None = None,
) -> Path:
    """Write a combined JSON evidence report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report_time = generated_at or datetime.now(SINGAPORE_TIMEZONE)
    report_time = report_time.astimezone(SINGAPORE_TIMEZONE)

    report = {
        "generated_at_sgt": report_time.isoformat(),
        "component": "attack_simulation",
        "components": sorted(
            {
                {
                    "CRYPTO": "crypto_payload",
                    "IMAGE": "image_stego",
                    "AUDIO": "audio_stego",
                }[result.test_id.split("-", 1)[0]]
                for result in results
            }
        ),
        "summary": {
            "total": len(results),
            "passed": sum(result.passed for result in results),
            "failed": sum(not result.passed for result in results),
            "attacks_detected": sum(
                result.attack_detected is True for result in results
            ),
        },
        "results": [asdict(result) for result in results],
    }

    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def build_evidence_path(
    generated_at: datetime,
    evidence_directory: str | Path = "evidence",
) -> Path:
    """Create a unique evidence filename using Singapore time."""

    singapore_time = generated_at.astimezone(SINGAPORE_TIMEZONE)
    timestamp = singapore_time.strftime("%Y%m%d_%H%M%S_%f")
    return Path(evidence_directory) / f"attack_results_{timestamp}_SGT.json"


def main() -> int:
    results = (
        run_crypto_attack_sweep()
        + run_image_attack_sweep()
        + run_audio_attack_sweep()
    )
    generated_at = datetime.now(SINGAPORE_TIMEZONE)
    output_path = build_evidence_path(generated_at)
    write_evidence(results, output_path, generated_at)

    print("Crypto, image and audio attack simulation")
    print("=" * 90)
    for result in results:
        status = "PASS" if result.passed else "SECURITY GAP"
        print(
            f"{result.test_id} | {result.attack:<32} | "
            f"verified={str(result.actual_verification):<5} | {status}"
        )
    print(f"Evidence written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
