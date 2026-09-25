"""PNG adapter; start-location policy belongs to start_location.py."""
from PIL import Image
from flask import current_app, has_request_context
from .start_location import CarrierSpec, WrongStartLocationError, embed_units, extract_units, required_units


def _web_demo_log():
    """Terminal output for classroom demos of real web uploads; never log keys.

    Set app.config['START_LOCATION_DEMO'] = False to disable index disclosure.
    """
    if has_request_context() and current_app.config.get("START_LOCATION_DEMO", True):
        return lambda message: print(f"[START LOCATION] {message}", flush=True)
    return None


def get_lsb_mask(num_bits: int) -> int:
    if not 1 <= num_bits <= 8:
        raise ValueError("LSB count must be between 1 and 8")
    return (1 << num_bits) - 1


def embed_bits_in_byte(cover_byte: int, secret_bits: int, num_bits: int) -> int:
    mask = get_lsb_mask(num_bits)
    return (cover_byte & ~mask & 0xFF) | (secret_bits & mask)


def extract_bits_from_byte(stego_byte: int, num_bits: int) -> int:
    return stego_byte & get_lsb_mask(num_bits)


def check_capacity(cover_width: int, cover_height: int, channels: int,
                   payload_size_bytes: int, bits_per_channel: int) -> tuple[bool, str]:
    spec = CarrierSpec.image(cover_width, cover_height, channels, bits_per_channel)
    needed = required_units(payload_size_bytes, spec)
    if needed > spec.total_units:
        return False, (f"Payload and authenticated framing need {needed} channels; "
                       f"image provides {spec.total_units} at {bits_per_channel}-bit LSB.")
    return True, f"OK: {needed}/{spec.total_units} channels used (including authenticated framing)."


def embed_payload(image_path: str, output_path: str, payload: bytes,
                  key: str, bits_per_channel: int = 1) -> None:
    with Image.open(image_path) as source:
        img = source.convert("RGB")
    spec = CarrierSpec.image(*img.size, bits=bits_per_channel)
    pixels = embed_units(img.tobytes(), payload, key, spec, demo_log=_web_demo_log())
    Image.frombytes("RGB", img.size, bytes(pixels)).save(output_path, "PNG")


def extract_payload(image_path: str, key: str, bits_per_channel: int = 1) -> bytes:
    with Image.open(image_path) as source:
        img = source.convert("RGB")
    spec = CarrierSpec.image(*img.size, bits=bits_per_channel)
    demo_log = _web_demo_log()
    try:
        return extract_units(img.tobytes(), key, spec, demo_log=demo_log)
    except WrongStartLocationError as error:
        if demo_log:
            demo_log(f"UPLOAD RECOVERY FAILED | {error} | wrong key/settings, missing frame, or tampering")
        raise
