"""Shared input validation helpers for upload routes."""


def validate_upload(file, allowed_extensions: tuple[str, ...]) -> tuple[bool, str]:
    """Check a Flask-uploaded file exists and has an allowed extension.
    Returns (ok, error_message)."""
    if not file or file.filename == '':
        return False, "No file selected"
    if not file.filename.lower().endswith(allowed_extensions):
        return False, f"Only {', '.join(allowed_extensions)} files are supported"
    return True, ""


def validate_bits(raw_value, default: int = 1) -> tuple[int | None, str]:
    """Parse and validate the bits-per-channel form field.
    Returns (bits, error_message); bits is None if invalid."""
    try:
        bits = int(raw_value if raw_value is not None else default)
    except (TypeError, ValueError):
        return None, "Invalid bits per channel value"
    if bits < 1 or bits > 8:
        return None, "Bits per channel must be between 1 and 8"
    return bits, ""