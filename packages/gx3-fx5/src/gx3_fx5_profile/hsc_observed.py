"""Pure, caller-guarded HSC observed-form projection, separate from Neutral IR.

The version-1 profile contains structural guards only: a UNIT member digest
and 230 ordered record guards (tag, size, primary marker, payload digest).
Its authenticity and any official provenance must be verified by the caller.
Neither supplied guards nor this projection establish engineering authority.
No archive, filesystem, native application or network operations occur here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import struct
from typing import Literal


PROFILE_FORMAT = "plcman.fx5.hsc-observed-guards"
RECORD_COUNT = 230
MAX_UNIT_BYTES = 1_048_576
MAX_W3PA_BYTES = 4_194_304
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEMANTIC_SIZES = {14809: 80, 14780: 184, 14712: 336}


class HscObservedError(ValueError):
    """Invalid API input/profile, with a stable code and profile/input location."""

    def __init__(self, code: str, location: str):
        self.code = code
        self.location = location
        super().__init__(code + " at " + location)


@dataclass(frozen=True)
class HscObservedFinding:
    code: str
    entry: str
    offset: int | None
    tag: int | None


class _Unsupported(ValueError):
    def __init__(self, finding: HscObservedFinding):
        self.finding = finding
        super().__init__(finding.code)


@dataclass(frozen=True)
class HscObservedSettings:
    status: Literal["OBSERVED_FORM", "UNSUPPORTED"]
    specification_method: Literal["NORMAL"] | None
    channel_use_vector: Literal["ALL_NOT_USE_OBSERVED_VECTOR"] | None
    raw_channel_flags: tuple[int, ...]
    unit_sha256: str
    w3pa_sha256: str
    guard_profile_sha256: str
    findings: tuple[HscObservedFinding, ...]
    counter_device: None = None
    counter_device_status: Literal["UNKNOWN"] = "UNKNOWN"
    qualification: str = "CALLER_GUARDED_OBSERVED_FORM_ONLY"
    semantic_authority: str = "NOT_ESTABLISHED"
    project_complete: bool = False


def _input(condition: bool, code: str, location: str = "/") -> None:
    if not condition:
        raise HscObservedError(code, location)


def _observed(condition: bool, code: str, offset: int | None = 0,
              tag: int | None = None, entry: str = "w3pa") -> None:
    if not condition:
        raise _Unsupported(HscObservedFinding(code, entry, offset, tag))


def _is_digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _profile(profile: object) -> tuple[str, tuple[tuple[int, int, int, str], ...], str]:
    _input(type(profile) is dict, "PROFILE_SCHEMA")
    _input(set(profile) == {"format", "version", "unit_sha256", "records"}, "PROFILE_SCHEMA")
    _input(profile["format"] == PROFILE_FORMAT, "PROFILE_FORMAT")
    _input(type(profile["version"]) is int and profile["version"] == 1, "PROFILE_VERSION")
    _input(_is_digest(profile["unit_sha256"]), "PROFILE_DIGEST")
    rows = profile["records"]
    _input(type(rows) is list and len(rows) == RECORD_COUNT, "PROFILE_RECORD_COUNT")
    guards = []
    tags = set()
    total = 0
    for index, row in enumerate(rows):
        location = "/records/" + str(index)
        _input(type(row) is dict and set(row) == {"tag", "size", "primary", "payload_sha256"},
               "PROFILE_RECORD_SCHEMA", location)
        tag, size, primary = row["tag"], row["size"], row["primary"]
        _input(type(tag) is int and 0 <= tag <= 0xFFFFFFFF, "PROFILE_TAG", location + "/tag")
        _input(type(size) is int and 76 <= size <= MAX_W3PA_BYTES, "PROFILE_SIZE", location + "/size")
        _input(type(primary) is int and primary in (1, 2, 4), "PROFILE_PRIMARY", location + "/primary")
        _input(tag not in tags, "PROFILE_DUPLICATE_TAG", location + "/tag")
        _input(_is_digest(row["payload_sha256"]), "PROFILE_DIGEST", location + "/payload_sha256")
        if tag in _SEMANTIC_SIZES:
            _input(size == _SEMANTIC_SIZES[tag] and primary == 4, "PROFILE_OBSERVED_STRUCTURE", location)
        tags.add(tag)
        total += size
        _input(total <= MAX_W3PA_BYTES, "PROFILE_BYTE_LIMIT", location + "/size")
        guards.append((tag, size, primary, row["payload_sha256"]))
    _input(set(_SEMANTIC_SIZES) <= tags, "PROFILE_REQUIRED_TAG")
    # Snapshot only validated primitive guards; later decoding does not consult
    # mutable caller dictionaries. This digest is identity, not authentication.
    canonical = {"format": PROFILE_FORMAT, "version": 1, "unit_sha256": profile["unit_sha256"],
                 "records": [{"tag": t, "size": s, "primary": p, "payload_sha256": d}
                             for t, s, p, d in guards]}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("ascii")
    return canonical["unit_sha256"], tuple(guards), hashlib.sha256(encoded).hexdigest()


def _nested(payload: bytes, count: int, width: int, tag: int, offset: int) -> tuple[bytes, ...]:
    _observed(len(payload) >= 4 and struct.unpack_from("<I", payload)[0] == count,
              "NESTED_COUNT", offset, tag)
    at = 4
    values = []
    for index in range(count):
        _observed(at + 12 <= len(payload), "NESTED_TRUNCATED", offset + at, tag)
        marker, key, length = struct.unpack_from("<III", payload, at)
        _observed(marker == 1 and key == 0x80000000 + index, "NESTED_KEY_ORDER", offset + at + 4, tag)
        _observed(length == width and at + 12 + length <= len(payload), "NESTED_LENGTH", offset + at + 8, tag)
        at += 12
        values.append(payload[at:at + length])
        at += length
    _observed(at == len(payload), "NESTED_TRAILING", offset + at, tag)
    return tuple(values)


def _records(raw: bytes, guards: tuple[tuple[int, int, int, str], ...]) -> dict[int, tuple[bytes, int]]:
    at = 0
    selected = {}
    seen = set()
    for tag, size, primary, payload_digest in guards:
        _observed(at + 20 <= len(raw), "RECORD_TRUNCATED", at, tag)
        actual_size, actual_tag, marker1, marker2, actual_primary = struct.unpack_from("<5I", raw, at)
        _observed(actual_tag not in seen, "RECORD_DUPLICATE_TAG", at + 4, tag)
        _observed(actual_tag == tag, "RECORD_ORDER", at + 4, tag)
        _observed(actual_size == size and at + size <= len(raw), "RECORD_BOUNDARY", at, tag)
        _observed((marker1, marker2, actual_primary) == (1, 1, primary), "RECORD_MARKER", at + 8, tag)
        attrs_at = at + size - 56
        for index in range(4):
            attrs = struct.unpack_from("<IIIH", raw, attrs_at + index * 14)
            _observed(attrs == (0xFFFFFFFF, index + 1, 2, 1 if index == 0 else 0),
                      "RECORD_ATTRIBUTES", attrs_at + index * 14, tag)
        payload = raw[at + 20:attrs_at]
        _observed(hashlib.sha256(payload).hexdigest() == payload_digest, "PAYLOAD_CONTEXT_MISMATCH", at + 20, tag)
        if tag in _SEMANTIC_SIZES:
            selected[tag] = (payload, at + 20)
        seen.add(tag)
        at += size
    _observed(at == len(raw), "RECORD_TRAILING", at)
    return selected


def decode_hsc_observed_settings(unit: bytes, w3pa: bytes, profile: object) -> HscObservedSettings:
    """Project only fixed Normal/all-zero observations under caller guards.

    Malformed API inputs/profiles raise HscObservedError. Unrecognized member
    bytes return UNSUPPORTED with no supported settings. Profile digests cannot
    inject field meanings or override the three hardcoded semantic checks.
    Whole-project hashes/names are not accepted. Counter-device stays UNKNOWN.
    """
    _input(type(unit) is bytes and type(w3pa) is bytes, "IMMUTABLE_BYTES_REQUIRED")
    _input(len(unit) <= MAX_UNIT_BYTES and len(w3pa) <= MAX_W3PA_BYTES, "INPUT_BYTE_LIMIT")
    unit_guard, guards, profile_digest = _profile(profile)
    unit_digest = hashlib.sha256(unit).hexdigest()
    w3pa_digest = hashlib.sha256(w3pa).hexdigest()
    try:
        _observed(bool(unit) and unit_digest == unit_guard, "UNIT_CONTEXT_MISMATCH", None, None, "UNIT.PRM")
        selected = _records(w3pa, guards)
        other, other_offset = selected[14809]
        _observed(other == b"\x00\x00\x00\x00", "OTHER_CONTEXT_UNSUPPORTED", other_offset, 14809)
        flags = _nested(selected[14780][0], 8, 1, 14780, selected[14780][1])
        _observed(flags == (b"\x00",) * 8, "CHANNEL_VECTOR_UNSUPPORTED", selected[14780][1], 14780)
        coupled = _nested(selected[14712][0], 16, 4, 14712, selected[14712][1])
        _observed(coupled == (b"\x20\x00\x00\x00",) * 16, "COUPLED_CONTEXT_UNSUPPORTED", selected[14712][1], 14712)
    except _Unsupported as error:
        return HscObservedSettings("UNSUPPORTED", None, None, (), unit_digest,
                                   w3pa_digest, profile_digest, (error.finding,))
    return HscObservedSettings("OBSERVED_FORM", "NORMAL", "ALL_NOT_USE_OBSERVED_VECTOR",
                               (0,) * 8, unit_digest, w3pa_digest, profile_digest, ())
