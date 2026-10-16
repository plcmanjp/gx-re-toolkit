"""Pure projection of one caller-guarded CPU registration observation.

Inputs are immutable CPU.PRM/w3pa bytes, a complete same-artifact member
inventory, and version-1 opaque context guards. The caller must independently
verify inventory completeness, member origins, guard authenticity and native
provenance. Digests authenticate none of those claims. No archive/file IO occurs.

Only two fixed name-block forms are recognized; this is not a CPU grammar.
The QPG constant 0x4c has no established record-size interpretation here.
Singleton context is reported separately from an encoded CPU-to-POU ID edge.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import struct
from typing import Literal


PROFILE_FORMAT = "plcman.fx5.cpu-observed-guards"
MAX_CPU_BYTES = 1_048_576
MAX_W3PA_BYTES = 4_194_304
MAX_MEMBER_BYTES = 4_194_304
MAX_TOTAL_BYTES = 67_108_864
MAX_MEMBERS = 512
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_QPG = re.compile(r"ConvertData/[1-9][0-9]{0,19}/Program\.qpg\Z")
_LINK = re.compile(r"ConvertData/[1-9][0-9]{0,19}/PouLinkOrder\.info\Z")
_STEP = re.compile(r"[1-9][0-9]{0,19}_StepInfo\.db\Z")
_PCODE = re.compile(r"ConvertData/[1-9][0-9]{0,19}/PouPCode\.pcode\Z")
_CPU_FORMS = ((20, 14, 5), (24, 18, 9))
_QPG_PREFIX = struct.pack("<HIIIH", 0xFFFF, 0x4C, 0x60, 0xFFFFFFFF, 16)


class CpuObservedError(ValueError):
    """Invalid API/profile input, with a stable code and location."""

    def __init__(self, code: str, location: str):
        self.code, self.location = code, location
        super().__init__(code + " at " + location)


@dataclass(frozen=True)
class CpuObservedMember:
    entry: str
    body: bytes


@dataclass(frozen=True)
class CpuObservedFinding:
    code: str
    entry: str
    offset: int | None = None
    tag: int | None = None


@dataclass(frozen=True)
class CpuObservedMemberDigest:
    entry: str
    byte_count: int
    sha256: str


@dataclass(frozen=True)
class CpuObservedQpg:
    entry: str
    byte_count: int
    sha256: str
    linked: bool
    observed_name: str | None = None
    name_offset: int | None = None
    name_status: str = "UNKNOWN"


@dataclass(frozen=True)
class CpuObservedSettings:
    status: Literal["OBSERVED_FORM", "UNSUPPORTED"]
    observed_program_name: str | None
    observed_pou_name: str | None
    linked_pou_id: str | None
    link_entry: str | None
    step_info_entry: str | None
    pcode_entry: str | None
    cpu_name_offset: int | None
    w3pa_name_offset: int | None
    cpu_sha256: str
    w3pa_sha256: str
    guard_profile_sha256: str
    member_digests: tuple[CpuObservedMemberDigest, ...]
    qpg_census: tuple[CpuObservedQpg, ...]
    findings: tuple[CpuObservedFinding, ...]
    w3pa_entry: str | None = None
    binding_status: str = "UNKNOWN"
    observed_execution_context: str | None = None
    numeric_cpu_edge_status: str = "UNKNOWN"
    general_execution_type_status: str = "UNKNOWN"
    execution_order_status: str = "UNKNOWN"
    qpg_record_size_semantics: str = "UNKNOWN"
    qualification: str = "CALLER_GUARDED_OBSERVED_FORM_ONLY"
    semantic_authority: str = "NOT_ESTABLISHED"
    project_complete: bool = False


class _Unsupported(ValueError):
    def __init__(self, finding: CpuObservedFinding):
        self.finding = finding


def _input(ok: bool, code: str, location: str = "/") -> None:
    if not ok:
        raise CpuObservedError(code, location)


def _observed(ok: bool, code: str, entry: str, offset: int | None = None,
              tag: int | None = None) -> None:
    if not ok:
        raise _Unsupported(CpuObservedFinding(code, entry, offset, tag))


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 256 and
            not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in value) and
            all(part not in ("", ".", "..") for part in value.split("/")))


def _inventory_path(value: object) -> bool:
    # Explicit ZIP directory entries are inventory evidence, not guard targets.
    # Remove only one terminal slash; the regular path checks still reject a
    # root, double separators and dot/dot-dot components.
    return (type(value) is str and len(value) <= 256 and
            _path(value[:-1] if value.endswith("/") else value))


def _related(entry: str) -> bool:
    return any(pattern.fullmatch(entry) for pattern in (_QPG, _LINK, _STEP, _PCODE))


def _profile(value: object) -> tuple[tuple[str, str], tuple[str, str],
                                     tuple[tuple[str, int, str], ...], str]:
    _input(type(value) is dict and set(value) == {
        "format", "version", "cpu_context", "w3pa_context", "member_guards"}, "PROFILE_SCHEMA")
    _input(value["format"] == PROFILE_FORMAT, "PROFILE_FORMAT", "/format")
    _input(type(value["version"]) is int and value["version"] == 1,
           "PROFILE_VERSION", "/version")
    contexts = []
    for key in ("cpu_context", "w3pa_context"):
        row = value[key]
        _input(type(row) is dict and set(row) == {"prefix_sha256", "suffix_sha256"},
               "PROFILE_CONTEXT_SCHEMA", "/" + key)
        pair = tuple(row[name] for name in ("prefix_sha256", "suffix_sha256"))
        for name, digest in zip(("prefix_sha256", "suffix_sha256"), pair):
            _input(type(digest) is str and _DIGEST.fullmatch(digest) is not None,
                   "PROFILE_DIGEST", "/" + key + "/" + name)
        contexts.append(pair)
    rows = value["member_guards"]
    _input(type(rows) is list and 1 <= len(rows) <= MAX_MEMBERS,
           "PROFILE_MEMBER_COUNT", "/member_guards")
    guards = []
    seen = set()
    total = 0
    for index, row in enumerate(rows):
        at = "/member_guards/" + str(index)
        _input(type(row) is dict and set(row) == {"entry", "byte_count", "sha256"},
               "PROFILE_MEMBER_SCHEMA", at)
        entry, count, digest = row["entry"], row["byte_count"], row["sha256"]
        _input(_path(entry) and _related(entry), "PROFILE_MEMBER_ENTRY", at + "/entry")
        _input(entry.casefold() not in seen, "PROFILE_DUPLICATE_ENTRY", at + "/entry")
        _input(type(count) is int and 0 < count <= MAX_MEMBER_BYTES,
               "PROFILE_MEMBER_SIZE", at + "/byte_count")
        _input(type(digest) is str and _DIGEST.fullmatch(digest) is not None,
               "PROFILE_DIGEST", at + "/sha256")
        total += count
        _input(total <= MAX_TOTAL_BYTES, "PROFILE_BYTE_LIMIT", at)
        seen.add(entry.casefold())
        guards.append((entry, count, digest))
    guards.sort()
    canonical = {"format": PROFILE_FORMAT, "version": 1,
                 "cpu_context": dict(zip(("prefix_sha256", "suffix_sha256"), contexts[0])),
                 "w3pa_context": dict(zip(("prefix_sha256", "suffix_sha256"), contexts[1])),
                 "member_guards": [{"entry": e, "byte_count": n, "sha256": d}
                                   for e, n, d in guards]}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("ascii")
    return contexts[0], contexts[1], tuple(guards), _sha(encoded)


def _name(raw: bytes, entry: str, at: int, width: int) -> str:
    _observed(at + width <= len(raw), "NAME_TRUNCATED", entry, at)
    encoded = raw[at:at + width]
    _observed(encoded[-2:] == b"\0\0", "NAME_TERMINATOR", entry, at)
    try:
        name = encoded[:-2].decode("utf-16le", errors="strict")
    except UnicodeDecodeError:
        raise _Unsupported(CpuObservedFinding("NAME_UTF16", entry, at)) from None
    _observed(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None,
              "NAME_OBSERVED_ALPHABET", entry, at)
    return name


def _context(raw: bytes, start: int, end: int, guards: tuple[str, str], entry: str) -> None:
    _observed(_sha(raw[:start]) == guards[0], "PREFIX_CONTEXT_MISMATCH", entry, start)
    _observed(_sha(raw[end:]) == guards[1], "SUFFIX_CONTEXT_MISMATCH", entry, end)


def _cpu_name(raw: bytes, guards: tuple[str, str]) -> tuple[str, int]:
    # Match a unique structured header, not a token/name or an inferred record
    # length grammar. The integers below are raw observed tuples only.
    candidates = []
    at = raw.find(b"\xff\xff")
    while at != -1:
        if raw[at + 6:at + 10] == struct.pack("<I", 0x01003700):
            candidates.append(at)
            if len(candidates) > 1:
                break
        at = raw.find(b"\xff\xff", at + 1)
    _observed(len(candidates) == 1, "CPU_NAME_BLOCK_CARDINALITY", "CPU.PRM", None, 0x01003700)
    at = candidates[0]
    _observed(at + 16 <= len(raw), "CPU_HEADER_TRUNCATED", "CPU.PRM", at)
    marker, length, tag, count, internal, units = struct.unpack_from("<HIIHHH", raw, at)
    _observed(marker == 0xFFFF and tag == 0x01003700 and count == 1 and
              (length, internal, units) in _CPU_FORMS, "CPU_HEADER_FORM", "CPU.PRM", at, tag)
    name = _name(raw, "CPU.PRM", at + 16, units * 2)
    _context(raw, at, at + 16 + units * 2, guards, "CPU.PRM")
    return name, at + 16


def _w3pa_name(raw: bytes, guards: tuple[str, str], entry: str) -> tuple[str, int]:
    _observed(len(raw) >= 36, "W3PA_HEADER_TRUNCATED", entry, 0)
    header = struct.unpack_from("<9I", raw)
    _observed(header in ((386, 0x0E11, 1, 1, 4, 1, 1, 0x10000, 10),
                        (394, 0x0E11, 1, 1, 4, 1, 1, 0x10000, 18)),
              "W3PA_HEADER_FORM", entry, 0, 0x0E11)
    name = _name(raw, entry, 36, header[8])
    _context(raw, 0, 36 + header[8], guards, entry)
    return name, 36


def decode_cpu_observed_settings(cpu_prm: bytes, cpu_w3pa: bytes,
                                 members: tuple[CpuObservedMember, ...],
                                 profile: object) -> CpuObservedSettings:
    """Return a narrow name/context projection; malformed profiles raise.

    ``members`` is the complete same-artifact inventory, not just linked QPGs.
    Explicit directory entries must have an empty body and one terminal slash;
    they remain present in member_digests and the inventory denominator.
    Only QPG/link/StepInfo/Pcode entries appear in ``member_guards``; unrelated
    inventory bytes are censused/digested but do not acquire decoded semantics.
    CPU prefix excludes the 16-byte header and suffix begins after name+NUL;
    w3pa prefix is empty and suffix begins after its fixed header/name+NUL.
    Profile guards may be shared by the two observed name-length forms.
    CPU.PRM must match its inventory entry; w3pa bytes must match exactly one
    canonical .w3pa member. This rejects contradictory input projections, but
    does not authenticate an inventory supplied or modified by the caller.

    SCAN_OBSERVED_CONTEXT_ONLY is the externally qualified observation context,
    not an enum decoded from CPU bytes. Consumers must check qualification and
    independently bound official evidence; this API cannot establish authority.
    """
    _input(type(cpu_prm) is bytes and type(cpu_w3pa) is bytes, "IMMUTABLE_BYTES_REQUIRED")
    _input(len(cpu_prm) <= MAX_CPU_BYTES and len(cpu_w3pa) <= MAX_W3PA_BYTES, "INPUT_BYTE_LIMIT")
    _input(type(members) is tuple and 1 <= len(members) <= MAX_MEMBERS, "MEMBER_INVENTORY")
    inventory = {}
    total = len(cpu_prm) + len(cpu_w3pa)
    for index, member in enumerate(members):
        location = "/members/" + str(index)
        _input(type(member) is CpuObservedMember and _inventory_path(member.entry), "MEMBER_ENTRY", location)
        _input(type(member.body) is bytes, "IMMUTABLE_BYTES_REQUIRED", location)
        _input(not member.entry.endswith("/") or member.body == b"",
               "DIRECTORY_BODY_NOT_EMPTY", location)
        _input(len(member.body) <= MAX_MEMBER_BYTES, "MEMBER_BYTE_LIMIT", location)
        identity = member.entry.removesuffix("/").casefold()
        _input(identity not in inventory, "DUPLICATE_MEMBER_ENTRY", location)
        inventory[identity] = member
        total += len(member.body)
        _input(total <= MAX_TOTAL_BYTES, "TOTAL_BYTE_LIMIT", location)
    cpu_guard, w3pa_guard, guards, profile_digest = _profile(profile)
    ordered = sorted(inventory.values(), key=lambda m: m.entry)
    by_entry = {member.entry: member.body for member in ordered}
    digests = tuple(CpuObservedMemberDigest(m.entry, len(m.body), _sha(m.body)) for m in ordered)
    # Include path aliases in the census, then reject them; never silently omit
    # a differently cased or noncanonical Program.qpg/PouLinkOrder.info entry.
    qpgs = [m for m in ordered if m.entry.casefold().endswith("/program.qpg") or
            m.entry.casefold() == "program.qpg"]
    links = [m for m in ordered if m.entry.casefold().endswith("/poulinkorder.info") or
             m.entry.casefold() == "poulinkorder.info"]
    census = tuple(CpuObservedQpg(m.entry, len(m.body), _sha(m.body), False) for m in qpgs)
    common = dict(cpu_sha256=_sha(cpu_prm), w3pa_sha256=_sha(cpu_w3pa),
                  guard_profile_sha256=profile_digest, member_digests=digests,
                  w3pa_entry=None)
    try:
        _observed("CPU.PRM" in by_entry and by_entry["CPU.PRM"] == cpu_prm,
                  "CPU_INVENTORY_MISMATCH", "CPU.PRM")
        mirrors = [m for m in ordered if m.entry.casefold().endswith(".w3pa") and m.body == cpu_w3pa]
        _observed(len(mirrors) == 1 and mirrors[0].entry.endswith(".w3pa"),
                  "W3PA_INVENTORY_MATCH_CARDINALITY", "members")
        w3pa_entry = mirrors[0].entry
        common["w3pa_entry"] = w3pa_entry
        target_aliases = [m for m in ordered if
                          (m.entry.casefold().endswith("_stepinfo.db") and not _STEP.fullmatch(m.entry)) or
                          (m.entry.casefold().endswith("/poupcode.pcode") and not _PCODE.fullmatch(m.entry))]
        _observed(all(_QPG.fullmatch(m.entry) for m in qpgs) and
                  all(_LINK.fullmatch(m.entry) for m in links) and not target_aliases,
                  "NONCANONICAL_TOPOLOGY_ENTRY", "members")
        _observed(len(qpgs) == 2 and len(links) == 1, "SINGLETON_CENSUS_UNSUPPORTED", "members")
        related = {e: b for e, b in by_entry.items() if _related(e)}
        _observed(set(related) == {e for e, _, _ in guards}, "MEMBER_GUARD_CENSUS", "members")
        for entry, count, digest in guards:
            body = related[entry]
            _observed(len(body) == count and _sha(body) == digest, "MEMBER_CONTEXT_MISMATCH", entry)
        program, cpu_at = _cpu_name(cpu_prm, cpu_guard)
        other_name, w3pa_at = _w3pa_name(cpu_w3pa, w3pa_guard, w3pa_entry)
        _observed(program == other_name, "CPU_W3PA_NAME_MISMATCH", w3pa_entry, w3pa_at)
        link = links[0]
        _observed(re.fullmatch(rb"[1-9][0-9]{19}\n", link.body) is not None,
                  "LINK_ID_OBSERVED_FORM", link.entry, 0)
        identity = link.body[:-1].decode("ascii")
        qpg_entry = link.entry.rsplit("/", 1)[0] + "/Program.qpg"
        step, pcode = identity + "_StepInfo.db", "ConvertData/" + identity + "/PouPCode.pcode"
        _observed(qpg_entry in related and step in related and pcode in related,
                  "LINK_TARGET_MISSING", link.entry)
        _observed(sum(bool(_STEP.fullmatch(e)) for e in related) == 1 and
                  sum(bool(_PCODE.fullmatch(e)) for e in related) == 1,
                  "LINK_TARGET_CARDINALITY", link.entry)
        qpg = related[qpg_entry]
        start = qpg.find(_QPG_PREFIX)
        _observed(start >= 0 and qpg.find(_QPG_PREFIX, start + 1) == -1,
                  "QPG_NAME_BLOCK_CARDINALITY", qpg_entry, None, 0x60)
        pou_name = _name(qpg, qpg_entry, start + len(_QPG_PREFIX), 16)
        census = tuple(CpuObservedQpg(m.entry, len(m.body), _sha(m.body), m.entry == qpg_entry,
                                     pou_name if m.entry == qpg_entry else None,
                                     start + 16 if m.entry == qpg_entry else None,
                                     "OBSERVED_NAME_FIELD" if m.entry == qpg_entry else "UNKNOWN")
                       for m in qpgs)
        findings = tuple(CpuObservedFinding("UNLINKED_QPG_UNKNOWN", q.entry) for q in census if not q.linked)
    except _Unsupported as error:
        return CpuObservedSettings("UNSUPPORTED", None, None, None, None, None, None,
                                   None, None, **common, qpg_census=census, findings=(error.finding,))
    return CpuObservedSettings("OBSERVED_FORM", program, pou_name, identity, link.entry,
                               step, pcode, cpu_at, w3pa_at, **common, qpg_census=census,
                               findings=findings, binding_status="OBSERVED_SINGLETON_CONTEXT",
                               observed_execution_context="SCAN_OBSERVED_CONTEXT_ONLY")
