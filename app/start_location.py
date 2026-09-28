"""Sole owner of the project's variable start-location scheme (image + PCM)."""

from dataclasses import dataclass, replace
import hmac
import json
import secrets
import struct
from typing import Sequence

MAGIC = b"SL02"
_PREFIX = struct.Struct(">4s16sQ")
TAG_BYTES = 32
HEADER_BYTES = _PREFIX.size + TAG_BYTES


class WrongStartLocationError(ValueError):
    """Wrong location/key/settings, missing frame, or modified embedded data.

    These causes cannot be reliably distinguished from authentication failure.
    """


class PayloadMissingError(WrongStartLocationError):
    """No recognizable frame at the selected LSB depth.

    A damaged marker or wrong settings combined with a wrong key can also cause
    this result. Extraction probes other depths before reporting a missing frame.
    Subclassing preserves callers that catch all location/recovery failures.
    """


@dataclass(frozen=True)
class CarrierSpec:
    media: str
    total_units: int
    bits_per_unit: int
    unit_width: int
    dimensions: tuple[int, ...]

    def __post_init__(self):
        if self.media not in ("image", "audio"):
            raise ValueError("media must be image or audio")
        if self.unit_width not in (8, 16, 24, 32):
            raise ValueError("unsupported channel/sample width")
        if not 1 <= self.bits_per_unit <= min(8, self.unit_width):
            raise ValueError("LSB count must be between 1 and 8")
        if self.total_units <= 0 or not self.dimensions or any(d <= 0 for d in self.dimensions):
            raise ValueError("carrier dimensions must be positive")

    @classmethod
    def image(cls, width, height, channels=3, bits=1):
        return cls("image", width * height * channels, bits, 8, (width, height, channels))

    @classmethod
    def audio(cls, frames, channels, sample_rate, sample_width=16, bits=1):
        """One unit is one PCM sample; multichannel samples are interleaved."""
        return cls("audio", frames * channels, bits, sample_width,
                   (frames, channels, sample_rate))

    @property
    def header_units(self):
        return _units(HEADER_BYTES, self.bits_per_unit)

    def context(self):
        return json.dumps(["start-location-v2", self.media, self.total_units,
                           self.bits_per_unit, self.unit_width, self.dimensions],
                          separators=(",", ":")).encode("ascii")


def _units(byte_count, bits):
    return (byte_count * 8 + bits - 1) // bits


def required_units(payload_size: int, spec: CarrierSpec) -> int:
    if payload_size < 0:
        raise ValueError("payload size cannot be negative")
    return spec.header_units + _units(payload_size + TAG_BYTES, spec.bits_per_unit)


def _subkey(key, label):
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, bytes) or not key:
        raise ValueError("a nonempty shared secret is required")
    return hmac.digest(key, b"start-location-v2/" + label, "sha256")


def _mac(key, label, spec, data):
    return hmac.digest(_subkey(key, label), spec.context() + b"\x00" + data, "sha256")


def derive_payload_positions(key, spec: CarrierSpec, nonce: bytes, unit_count: int):
    """Yield distinct absolute indices using a keyed sparse Fisher-Yates shuffle.

    No full carrier-sized array is allocated. A sparse swap map takes O(k)
    memory for k requested positions. Selection has no duplicate retries, even
    at full capacity. Rejection sampling removes modulo bias. Prefixes are
    independent of requested length, so the first position is the start index.
    """
    if len(nonce) != 16:
        raise ValueError("nonce must contain 16 bytes")
    slots = spec.total_units - spec.header_units
    if slots <= 0 or slots >= 2**256:
        raise ValueError("carrier has no usable start-location region")
    if type(unit_count) is not int or not 0 <= unit_count <= slots:
        raise ValueError("position count exceeds usable carrier capacity")
    base = hmac.new(_subkey(key, b"positions"),
                    spec.context() + b"\x00" + nonce, "sha256")
    counter = 0
    swaps = {}
    for remaining in range(slots, slots - unit_count, -1):
        limit = 2**256 - (2**256 % remaining)
        while True:
            digest = base.copy()
            digest.update(counter.to_bytes(32, "big"))
            counter += 1
            value = int.from_bytes(digest.digest(), "big")
            if value < limit:
                break
        chosen = value % remaining
        position = swaps.get(chosen, chosen)
        last = remaining - 1
        replacement = swaps.pop(last, last)
        if chosen != last:
            swaps[chosen] = replacement
        yield spec.header_units + position


def derive_start_location(key, spec: CarrierSpec, nonce: bytes) -> int:
    """The first position in the shared keyed embedding sequence."""
    return next(derive_payload_positions(key, spec, nonce, 1))


def select_start_location(key, spec: CarrierSpec, payload_size: int):
    """Encoder: return (start index, authenticated bootstrap header)."""
    if required_units(payload_size, spec) > spec.total_units:
        raise ValueError("Payload and authenticated framing exceed carrier capacity")
    nonce = secrets.token_bytes(16)
    prefix = _PREFIX.pack(MAGIC, nonce, payload_size)
    header = prefix + _mac(key, b"header", spec, prefix)
    return derive_start_location(key, spec, nonce), header


def recover_start_location(key, spec: CarrierSpec, header: bytes):
    """Decoder: authenticate before trusting length; return (index, length)."""
    if len(header) != HEADER_BYTES:
        raise WrongStartLocationError("Wrong Start Location: invalid bootstrap size")
    if header[:4] == b"SL01":
        raise WrongStartLocationError("Unsupported legacy SL01 format: embed the original cover again")
    if header[:len(MAGIC)] != MAGIC:
        raise PayloadMissingError("Payload Missing: no recognizable embedded header")
    prefix, tag = header[:-TAG_BYTES], header[-TAG_BYTES:]
    if not hmac.compare_digest(tag, _mac(key, b"header", spec, prefix)):
        raise WrongStartLocationError("Wrong Start Location: bootstrap authentication failed")
    magic, nonce, length = _PREFIX.unpack(prefix)
    if magic != MAGIC or required_units(length, spec) > spec.total_units:
        raise WrongStartLocationError("Wrong Start Location: invalid frame or capacity")
    return derive_start_location(key, spec, nonce), length


def _io_positions(spec, count, bootstrap, positions):
    if bootstrap:
        if count > spec.header_units:
            raise ValueError("Bootstrap exceeds reserved header region")
        return iter(range(count))
    if positions is None:
        raise ValueError("Payload I/O requires keyed positions")
    return iter(positions)


def _write(units, data, spec, start, bootstrap=False, *, positions=None):
    bits = spec.bits_per_unit
    mask = (1 << bits) - 1
    accumulator = available = 0
    indices = _io_positions(spec, _units(len(data), bits), bootstrap, positions)
    for byte in data:
        accumulator = (accumulator << 8) | byte
        available += 8
        while available >= bits:
            available -= bits
            index = next(indices)
            units[index] = (units[index] & ~mask) | ((accumulator >> available) & mask)
        accumulator &= (1 << available) - 1
    if available:
        index = next(indices)
        units[index] = (units[index] & ~mask) | (accumulator << (bits - available))


def _read(units, byte_count, spec, start, bootstrap=False, *, positions=None):
    result = bytearray()
    accumulator = available = 0
    mask = (1 << spec.bits_per_unit) - 1
    count = _units(byte_count, spec.bits_per_unit)
    indices = _io_positions(spec, count, bootstrap, positions)
    for _ in range(count):
        index = next(indices)
        accumulator = (accumulator << spec.bits_per_unit) | (units[index] & mask)
        available += spec.bits_per_unit
        while available >= 8 and len(result) < byte_count:
            available -= 8
            result.append((accumulator >> available) & 255)
        accumulator &= (1 << available) - 1
    return bytes(result)


def embed_units(units: Sequence[int], payload: bytes, key, spec: CarrierSpec, *, demo_log=None,
                prepared_header=None) -> list[int]:
    """Return a modified copy of RGB channels or signed/unsigned PCM samples."""
    if len(units) != spec.total_units:
        raise ValueError("carrier length does not match specification")
    if prepared_header is None:
        start, header = select_start_location(key, spec, len(payload))
    else:
        # Audio selects once before hashing the exact occupied sample region.
        # Authenticate the prepared layout and prohibit changing its length.
        header = prepared_header
        start, length = recover_start_location(key, spec, header)
        if length != len(payload):
            raise ValueError("Prepared header length does not match payload")
    tag = _mac(key, b"payload", spec, header + start.to_bytes(32, "big") + payload)
    output = list(units)
    _write(output, header, spec, 0, bootstrap=True)
    count = _units(len(payload) + TAG_BYTES, spec.bits_per_unit)
    _write(output, payload + tag, spec, start,
           positions=derive_payload_positions(key, spec, header[4:20], count))
    if demo_log:
        demo_log(f"ENCODER | nonce={header[4:20].hex()} | media={spec.media} | "
                 f"LSBs={spec.bits_per_unit} | derived start index={start} (zero-based)")
        demo_log(f"ENCODER positions (first 10): {list(derive_payload_positions(key, spec, header[4:20], min(10, count)))}")
    return output


def extract_units(units: Sequence[int], key, spec: CarrierSpec, *, start_index=None, demo_log=None) -> bytes:
    """Recover and authenticate data. Optional explicit index detects wrong starts."""
    if len(units) != spec.total_units:
        raise WrongStartLocationError("Wrong Start Location: carrier length does not match settings")
    try:
        if spec.total_units < spec.header_units:
            raise PayloadMissingError("Payload Missing: carrier too small for an embedded header")
        header = _read(units, HEADER_BYTES, spec, 0, bootstrap=True)
        start, length = recover_start_location(key, spec, header)
    except PayloadMissingError:
        # Read only the fixed-size header at other depths. Require its HMAC
        # and capacity checks to pass: a magic-byte coincidence is not evidence.
        # Diagnose the setting mismatch without silently extracting at another depth.
        for bits in range(1, min(8, spec.unit_width) + 1):
            if bits == spec.bits_per_unit:
                continue
            candidate = replace(spec, bits_per_unit=bits)
            if candidate.total_units < candidate.header_units:
                continue
            candidate_header = _read(units, HEADER_BYTES, candidate, 0, bootstrap=True)
            try:
                recover_start_location(key, candidate, candidate_header)
            except WrongStartLocationError:
                continue
            raise WrongStartLocationError(
                f"Wrong Start Location: selected {spec.bits_per_unit} LSBs, "
                f"but an authenticated header was found at {bits} LSBs"
            ) from None
        raise
    if demo_log:
        demo_log(f"DECODER | nonce={header[4:20].hex()} | media={spec.media} | "
                 f"LSBs={spec.bits_per_unit} | recovered start index={start} (zero-based)")
    if start_index is not None and start_index != start:
        raise WrongStartLocationError("Wrong Start Location: supplied index differs from derived index")
    count = _units(length + TAG_BYTES, spec.bits_per_unit)
    frame = _read(units, length + TAG_BYTES, spec, start,
                  positions=derive_payload_positions(key, spec, header[4:20], count))
    payload, tag = frame[:-TAG_BYTES], frame[-TAG_BYTES:]
    expected = _mac(key, b"payload", spec, header + start.to_bytes(32, "big") + payload)
    if not hmac.compare_digest(tag, expected):
        raise WrongStartLocationError("Wrong Start Location: payload authentication failed (or tampered data)")
    if demo_log:
        demo_log(f"DECODER positions (first 10): {list(derive_payload_positions(key, spec, header[4:20], min(10, count)))}")
        demo_log("RECOVERY | PASS: payload authentication succeeded at recovered index")
        # Rotate every selected position by one within the payload region.
        # This is a deliberately wrong sequence, not a second derivation scheme.
        wrong = spec.header_units + (start - spec.header_units + 1) % (
            spec.total_units - spec.header_units)
        slots = spec.total_units - spec.header_units
        wrong_positions = (spec.header_units + (index - spec.header_units + 1) % slots
                           for index in derive_payload_positions(key, spec, header[4:20], count))
        wrong_frame = _read(units, length + TAG_BYTES, spec, wrong, positions=wrong_positions)
        wrong_expected = _mac(key, b"payload", spec,
                              header + wrong.to_bytes(32, "big") + wrong_frame[:-TAG_BYTES])
        valid = hmac.compare_digest(wrong_frame[-TAG_BYTES:], wrong_expected)
        result = "UNEXPECTED authentication success" if valid else "Wrong Start Location: HMAC rejected"
        demo_log(f"WRONG-INDEX EXPERIMENT | attempted index={wrong} | {result} | "
                 "demo experiment only; actual upload recovery succeeded")
    return payload
