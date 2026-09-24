"""Automated attacks against the crypto payload and image steganography modules."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image

from app.crypto_payload import (
    build_payload,
    generate_keypair,
    hash_cover_object,
    run_verification,
    sign_payload,
    stable_hash,
    verify_payload,
)
from app.image_stego import embed_payload, extract_payload


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


def run_crypto_attack_sweep() -> list[AttackResult]:
    """Run attacks that only depend on the standalone crypto module."""

    private_key, public_key = generate_keypair()
    _, wrong_public_key = generate_keypair()

    cover_hash = hash_cover_object(b"original cover object")
    payload = build_payload("IMG001", cover_hash, {"team": "P6-7"})
    signature = sign_payload(private_key, payload)
    results: list[AttackResult] = []

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
) -> tuple[str, dict | None]:
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

        verdict, _ = _verify_image(
            baseline_path, correct_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-POS-01",
                "baseline_valid_stego_image",
                True,
                verdict == "Authentic",
                f"Valid stego image verification; verdict={verdict}.",
                is_attack=False,
            )
        )

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
                verdict == "Authentic",
                f"Changed signed metadata while retaining its signature; verdict={verdict}.",
            )
        )

        verdict, _ = _verify_image(
            baseline_path, correct_start_key, bits, wrong_public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-02",
                "wrong_public_key",
                False,
                verdict == "Authentic",
                f"Used an unrelated RSA public key; verdict={verdict}.",
            )
        )

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
                verdict == "Authentic", # Actual result evaluated at runtime
                f"Corrupted the embedded signature; verdict={verdict}.",
            )
        )

        verdict, _ = _verify_image(
            baseline_path, wrong_start_key, bits, public_key
        )
        results.append(
            _result(
                "IMAGE-NEG-04",
                "wrong_start_location",
                False,
                verdict == "Authentic",
                f"Derived extraction position using the wrong key; verdict={verdict}.",
            )
        )

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
                verdict == "Authentic",
                f"Changed a non-LSB cover-image bit; verdict={verdict}.",
            )
        )

        maximum_payload_bytes = (96 * 96 * 3 * bits // 8) - 4
        oversized_rejected = False
        rejection_message = "No capacity error was raised."
        try:
            embed_payload(
                str(cover_path),
                str(workdir / "oversized.png"),
                b"X" * (maximum_payload_bytes + 1),
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
                not oversized_rejected,
                f"Exceeded calculated image capacity by one byte; {rejection_message}",
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
                "crypto_payload"
                if result.test_id.startswith("CRYPTO-")
                else "image_stego"
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
    results = run_crypto_attack_sweep() + run_image_attack_sweep()
    generated_at = datetime.now(SINGAPORE_TIMEZONE)
    output_path = build_evidence_path(generated_at)
    write_evidence(results, output_path, generated_at)

    print("Crypto and image attack simulation")
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
