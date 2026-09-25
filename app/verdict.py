"""Shared verdict vocabulary (FR10) and orchestration-level error mapping."""

from enum import Enum


class Verdict(str, Enum):
    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"


def verdict_from_exception(exc: Exception) -> tuple[Verdict, str]:
    """Map an exception raised by any module into a verdict + explanation,
    so routes never leak a raw traceback to the user."""
    if isinstance(exc, NotImplementedError):
        return Verdict.CANNOT_VERIFY, f"Feature not yet implemented: {exc}"
    return Verdict.CANNOT_VERIFY, f"Unexpected error: {exc}"