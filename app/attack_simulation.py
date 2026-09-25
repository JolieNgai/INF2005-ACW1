"""Automated security attacks against the standalone crypto/payload module.

This module deliberately does not modify ``crypto_payload.py``.  It consumes the
same public functions as the future image and audio workflows, records the
verification outcome for each controlled attack, and can export reproducible
JSON evidence.
"""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.crypto_payload import (
    build_payload,
    generate_keypair,
    hash_cover_object,
    sign_payload,
    verify_payload,
)


SINGAPORE_TIMEZONE = timezone(timedelta(hours=8), name="SGT")


@dataclass(frozen=True)
class AttackResult:
    """One verification result produced by the attack simulation."""

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
    """Run all attacks currently possible without image/audio steganography.

    Replay and substitution are intentionally expected to be rejected.  With
    the current crypto-only verifier they are accepted, so those records expose
    a security limitation instead of hiding it.
    """

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

    # A captured, unchanged payload/signature pair remains cryptographically
    # valid. Detecting replay requires nonce/timestamp state outside this API.
    verified = verify_payload(public_key, payload, signature)
    results.append(
        _result(
            "CRYPTO-NEG-04",
            "replay_attempt",
            False,
            verified,
            "Reused the exact captured payload and signature; no replay cache or freshness check exists.",
        )
    )

    # A different payload that was legitimately signed also verifies because
    # verify_payload has no expected media identifier/context parameter.
    substituted_payload = build_payload(
        "IMG999", hash_cover_object(b"different cover object"), {"team": "P6-7"}
    )
    substituted_signature = sign_payload(private_key, substituted_payload)
    verified = verify_payload(
        public_key, substituted_payload, substituted_signature
    )
    results.append(
        _result(
            "CRYPTO-NEG-05",
            "signed_payload_substitution",
            False,
            verified,
            "Substituted another correctly signed payload for a different media ID; no expected-context check exists.",
        )
    )

    return results


def write_evidence(
    results: list[AttackResult],
    output_path: str | Path,
    generated_at: datetime | None = None,
) -> Path:
    """Write a JSON evidence report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report_time = generated_at or datetime.now(SINGAPORE_TIMEZONE)
    report_time = report_time.astimezone(SINGAPORE_TIMEZONE)

    report = {
        "generated_at_sgt": report_time.isoformat(),
        "component": "crypto_payload",
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
    """Return a unique, filesystem-safe evidence path using Singapore time."""

    singapore_time = generated_at.astimezone(SINGAPORE_TIMEZONE)
    timestamp = singapore_time.strftime("%Y%m%d_%H%M%S_%f")
    filename = f"attack_results_{timestamp}_SGT.json"
    return Path(evidence_directory) / filename


def main() -> int:
    results = run_crypto_attack_sweep()
    generated_at = datetime.now(SINGAPORE_TIMEZONE)
    output_path = build_evidence_path(generated_at)
    write_evidence(results, output_path, generated_at)

    print("Crypto attack simulation")
    print("=" * 72)
    for result in results:
        status = "PASS" if result.passed else "SECURITY GAP"
        print(
            f"{result.test_id} | {result.attack:<28} | "
            f"verified={str(result.actual_verification):<5} | {status}"
        )
    print(f"Evidence written to: {output_path}")

    # A reported security gap is evidence, not a program execution error.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
