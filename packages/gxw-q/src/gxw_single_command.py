"""Fail-closed GXW single-command replacement.

This module deliberately admits only the replicated POU layout observed by the
public WT9 contract.  It does not search for a plausible byte location: XML
roles, the resolved two- or three-copy payload set, every byte in each payload, and all raw OLD hits
must agree before a candidate can be written.
"""
from __future__ import annotations

import struct
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import gxw_ladder_writer as W
import gxw_bounded_ole as bounded_ole
from gxw_bounded_xml import parse_xml
from gxw_ladder_reader import DEVICE, DISPATCH_05, INSTR, INSTR_NOOP, XFER_B
from wt9_fill_pou_body import PREFIX_05


ANCHOR = b"\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"
END = b"\x04\x34\x02\x04"
MODIFIERS = {0xf0, 0xf1, 0xf2, 0xf6, 0xf8}
BASE_TYPES = set(DEVICE) | {0xe8, 0xe9, 0xea, 0xeb, 0xec}


class Rejected(ValueError):
    """The evidence is incomplete or does not meet the public contract."""


@dataclass(frozen=True)
class Payload:
    stream: str
    start: int
    end: int
    data: bytes
    commands: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Target:
    name: str
    payloads: tuple[Payload, ...]
    offsets: tuple[tuple[str, int], ...]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise Rejected("truncated uint32")
    return struct.unpack_from("<I", data, offset)[0]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _only_child_text(element: ET.Element, name: str) -> str:
    found = [child.text or "" for child in element.iter() if _local(child.tag) == name]
    if len(found) != 1 or not found[0]:
        raise Rejected(f"XML {name} must occur exactly once per role")
    return found[0]


def pou_roles(path: str | Path) -> dict[str, dict[str, str]]:
    """Resolve exact POU .res/.Program.pou XML roles without regex fallback."""
    try:
        ole = bounded_ole.open_file(path)
        try:
            raw = bounded_ole.stream(ole, "projectdatalist.xml", limit=1024 * 1024)
        finally:
            ole.close()
        root = parse_xml(raw)
    except Exception as error:
        raise Rejected(f"projectdatalist.xml unavailable or malformed: {error}") from error
    roles: dict[str, dict[str, str]] = {}
    used_ids: set[str] = set()
    for entry in (node for node in root.iter() if _local(node.tag) == "D_Projectdata"):
        name = _only_child_text(entry, "szName")
        stream = _only_child_text(entry, "iID")
        if not stream.isascii() or not stream.isdecimal() or str(int(stream)) != stream:
            raise Rejected("XML iID is not a canonical decimal stream id")
        if name.endswith(".res"):
            pou, role = name[:-4], "res"
        elif name.endswith(".Program.pou"):
            pou, role = name[:-12], "prg"
        else:
            continue
        if not pou:
            raise Rejected("empty POU name")
        if stream in used_ids:
            raise Rejected("XML POU roles share an iID")
        used_ids.add(stream)
        current = roles.setdefault(pou, {})
        if role in current:
            raise Rejected("duplicate XML POU role")
        current[role] = stream
    if not roles or any(set(pair) != {"res", "prg"} for pair in roles.values()):
        raise Rejected("every XML POU role set must contain one .res and one .Program.pou")
    return roles


def _frame(data: bytes, offset: int) -> int:
    if offset + 3 > len(data):
        raise Rejected("truncated operand frame")
    marker = data[offset]
    if marker not in (4, 5, 6, 7):
        raise Rejected("operand frame marker")
    width = marker - 3
    end = offset + width + 3
    if end > len(data) or data[end - 1] != marker:
        raise Rejected("operand frame closing marker")
    return end


def _operand(data: bytes, offset: int) -> int:
    """Consume one unmodified complete operand frame from the narrow contract."""
    end = _frame(data, offset)
    typecode = data[offset + 1]
    width = data[offset] - 3
    if typecode in MODIFIERS:
        raise Rejected("operand modifiers are outside the single-command contract")
    if typecode not in BASE_TYPES:
        raise Rejected("unknown operand base type")
    if typecode == 0xec and width != 4:
        raise Rejected("E constant requires a four-byte value frame")
    if typecode in (0xe8, 0xea) and width not in (1, 2):
        raise Rejected("16-bit K/H constant frame width")
    if typecode in (0xe9, 0xeb) and not 1 <= width <= 4:
        raise Rejected("32-bit K/H constant frame width")
    return end


def _command(data: bytes, offset: int) -> int:
    """Consume one proven command exactly; no scan-to-operand recovery exists."""
    if offset + 3 <= len(data) and data[offset] == 3 and data[offset + 2] == 3:
        opcode = data[offset + 1]
        if opcode in INSTR_NOOP:
            return offset + 3
        if opcode in INSTR:
            return _operand(data, offset + 3)
        raise Rejected("unknown 03 command opcode")
    if offset + 5 <= len(data) and data[offset] == 5 and data[offset + 4] == 5:
        marker, arity_class, opcode = data[offset + 1:offset + 4]
        fixed = XFER_B.get(opcode) if marker == 0x4C else DISPATCH_05.get((marker, opcode))
        if fixed is None:
            raise Rejected("unsupported 05 command")
        mnemonic, arity = fixed
        if PREFIX_05.get(mnemonic) != (marker, arity_class, opcode):
            raise Rejected("05 header is outside the public exact allowlist")
        end = offset + 5
        for _ in range(arity):
            end = _operand(data, end)
        return end
    raise Rejected("unsupported command prefix")


def exact_command(value: bytes) -> None:
    if not value:
        raise Rejected("empty command")
    if _command(value, 0) != len(value):
        raise Rejected("OLD/NEW must each be one complete command")


def _line_statement(data: bytes, offset: int) -> int | None:
    if offset + 2 >= len(data) or data[offset + 1] != 0x80:
        return None
    length = data[offset]
    text_length = length - 4
    end = offset + 3 + text_length
    if (length < 5 or data[offset + 2] != (length + 1) // 2
            or end >= len(data) or data[end] != length):
        raise Rejected("malformed line statement")
    text = data[offset + 3:end]
    if not all(0x20 <= byte <= 0xff for byte in text):
        raise Rejected("line statement text grammar")
    return end + 1


def _note(data: bytes, offset: int) -> int | None:
    if offset + 5 > len(data) or data[offset + 1] != 0x82:
        return None
    length = data[offset]
    text_length = length - 4
    end = offset + 3 + text_length
    if (length < 5 or data[offset + 2] not in ((length + 1) // 2, 0x01)
            or end >= len(data) or data[end] != length):
        raise Rejected("malformed Note record")
    text = data[offset + 3:end]
    if not text or not all(0x20 <= byte <= 0xff for byte in text):
        raise Rejected("Note text grammar")
    return end + 1


def parse_payload(stream: str, start: int, data: bytes) -> Payload:
    if len(data) < len(END) or not data.endswith(END):
        raise Rejected("payload must end in 04 34 02 04")
    commands: list[tuple[int, int]] = []
    cursor, command_end = 0, len(data) - len(END)
    while cursor < command_end:
        line = _line_statement(data, cursor)
        if line is not None:
            cursor = line
            continue
        note = _note(data, cursor)
        if note is not None:
            cursor = note
            continue
        end = _command(data[:command_end], cursor)
        commands.append((cursor, end))
        cursor = end
    if cursor != command_end:
        raise Rejected("payload grammar did not consume all bytes")
    return Payload(stream, start, start + len(data), data, tuple(commands))


def _header_name(data: bytes, count: int, payload_start: int) -> None:
    if not 1 <= count <= 128 or payload_start > len(data):
        raise Rejected("header length range")
    raw = data[4:4 + 2 * count]
    try:
        raw.decode("utf-16le")
    except UnicodeDecodeError as error:
        raise Rejected("header display-name UTF-16 grammar") from error


def parse_res(stream: str, data: bytes, name: str) -> tuple[Payload, Payload | None]:
    count = _u32(data, 0)
    first_start = 56 + 2 * count
    _header_name(data, count, first_start)
    first_length = _u32(data, first_start - 4)
    first_end = first_start + first_length
    if first_end + 12 > len(data) or data[first_end:first_end + 8] != b"\0" * 8:
        raise Rejected(".res first payload boundary")
    second_length = _u32(data, first_end + 8)
    second_start, second_end = first_end + 12, first_end + 12 + second_length
    trailer = (b"\0" * 8 + struct.pack("<I", 1)
               + struct.pack("<I", len(name) + 1) + name.encode("utf-16le")
               + b"\0\0" + struct.pack("<II", 4, 1))
    if second_end > len(data) or data[second_end:] != trailer:
        raise Rejected(".res second payload trailer")
    first = parse_payload(stream, first_start, data[first_start:first_end])
    # An empty second representation is an observed absence, never an empty
    # command stream.  It yields the two-copy form (res first + prg) below.
    second = None if second_length == 0 else parse_payload(
        stream, second_start, data[second_start:second_end]
    )
    return first, second


def parse_prg(stream: str, data: bytes, name: str) -> Payload:
    count = _u32(data, 0)
    start = 77 + 2 * count
    _header_name(data, count, start)
    anchor = start - 16
    if anchor < 8 or data[anchor:start] != ANCHOR:
        raise Rejected(".Program.pou anchor or fixed payload start")
    left, right = _u32(data, anchor - 8), _u32(data, anchor - 4)
    if left != right or left < 20 or left - 20 != len(data) - start - 24:
        raise Rejected(".Program.pou paired lengths")
    if data[-24:] != b"\0" * 24:
        raise Rejected(".Program.pou trailing 24 zero bytes")
    return parse_payload(stream, start, data[start:-24])


def _hits(data: bytes, needle: bytes) -> list[int]:
    out, start = [], 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return out
        out.append(index)
        start = index + 1


def resolve(path: str | Path, streams: dict[str, bytes], old: bytes, hdb: bytes | None = None) -> Target:
    exact_command(old)
    roles = pou_roles(path)
    candidates: list[Target] = []
    for name, pair in roles.items():
        if pair["res"] not in streams or pair["prg"] not in streams:
            raise Rejected("XML POU stream missing from _hdb")
        # POU role uniqueness is global, but the body grammar is only authority
        # for the POU selected by OLD.  An unrelated POU with no OLD raw bytes
        # remains byte-for-byte preserved rather than being guessed or parsed.
        if not (_hits(streams[pair["res"]], old) or _hits(streams[pair["prg"]], old)):
            continue
        first, second = parse_res(pair["res"], streams[pair["res"]], name)
        third = parse_prg(pair["prg"], streams[pair["prg"]], name)
        payloads = (first, third) if second is None else (first, second, third)
        if any(payload.data != first.data for payload in payloads[1:]):
            raise Rejected("replicated POU payloads differ")
        logical = [
            [(a, b) for a, b in payload.commands if payload.data[a:b] == old]
            for payload in payloads
        ]
        if all(len(items) == 1 for items in logical):
            offsets = tuple((payload.stream, payload.start + items[0][0])
                            for payload, items in zip(payloads, logical, strict=True))
            candidates.append(Target(name, payloads, offsets))
        elif any(items for items in logical):
            raise Rejected("OLD has a partial or repeated logical command hit")
    if len(candidates) != 1:
        raise Rejected("canonical OLD logical hit must identify exactly one POU")
    raw = [(stream, offset) for stream, data in streams.items() for offset in _hits(data, old)]
    if len(raw) != len(candidates[0].offsets) or set(raw) != set(candidates[0].offsets):
        raise Rejected("_hdb raw OLD hits are not exactly the resolved POU copy offsets")
    # OLE sector positions are intentionally not inferred from olefile internals.
    # This container-wide count is an additional fail-closed ambiguity check; the
    # proof of ownership remains the exact substream slice set above.
    if hdb is not None and len(_hits(hdb, old)) != len(raw):
        raise Rejected("_hdb container OLD count has unmapped slack or metadata hits")
    return candidates[0]


def _replace_at(data: bytes, offset: int, old: bytes, new: bytes) -> bytes:
    if data[offset:offset + len(old)] != old:
        raise Rejected("candidate slice no longer contains OLD")
    return data[:offset] + new + data[offset + len(old):]


def _top_streams(path: Path) -> dict[str, bytes]:
    ole = bounded_ole.open_file(path)
    try:
        return bounded_ole.all_streams(ole)
    finally:
        ole.close()


def _verify_candidate(candidate: Path, before_top: dict[str, bytes], expected_hdb: bytes,
                      before_substreams: dict[str, bytes], target: Target, new: bytes) -> None:
    after_top = _top_streams(candidate)
    before_non_hdb = {k: v for k, v in before_top.items() if k != "_hdb"}
    after_non_hdb = {k: v for k, v in after_top.items() if k != "_hdb"}
    if before_non_hdb != after_non_hdb or after_top.get("_hdb") != expected_hdb:
        raise Rejected("top-level non-_hdb preservation check failed")
    after = W.hdb_substreams(expected_hdb)
    if set(after) != set(before_substreams):
        raise Rejected("candidate _hdb stream set changed")
    expected = dict(before_substreams)
    for stream, offset in target.offsets:
        old = next(payload.data[offset - payload.start:offset - payload.start + len(new)]
                   for payload in target.payloads
                   if payload.stream == stream and payload.start <= offset < payload.end)
        expected[stream] = _replace_at(expected[stream], offset, old, new)
    if after != expected:
        raise Rejected("candidate substream bytes differ from the three expected slices")


def apply(src: str | Path, old: bytes, new: bytes, in_place: bool, out: Path | None,
          allow_collision: bool) -> int:
    """Apply exactly one proven command in its resolved two- or three-copy set."""
    try:
        if in_place and out is not None:
            raise Rejected("--in-place and --out cannot be combined")
        exact_command(old)
        exact_command(new)
        if len(old) != len(new):
            raise Rejected("single-command replacement requires equal byte length")
        source = Path(src)
        source_hash = W.source_sha256(source)
        before_top = _top_streams(source)
        hdb = before_top.get("_hdb")
        if hdb is None:
            raise Rejected("top-level _hdb missing")
        streams = W.hdb_substreams(hdb)
        target = resolve(source, streams, old, hdb)
        new_hits = sum(len(_hits(data, new)) for data in streams.values())
        if new_hits and not allow_collision:
            raise Rejected("NEW already occurs in _hdb; use existing --allow-collision policy")
        replacements: dict[str, bytes] = {}
        for stream, offset in target.offsets:
            previous = replacements.get(stream, streams[stream])
            replacements[stream] = _replace_at(previous, offset, old, new)
        with tempfile.TemporaryDirectory(prefix="gxw-single-") as temporary:
            new_hdb = W.patch_hdb_substreams(hdb, replacements, Path(temporary) / "work.ole")
        candidate = None
        try:
            candidate, destination, backup = W.prepare_candidate(source, out, in_place, expected_sha256=source_hash)
            W.write_top_hdb(candidate, new_hdb)
            _verify_candidate(candidate, before_top, new_hdb, streams, target, new)
            rc, _ = W.self_check(candidate)
            if rc != 0:
                print(f"  중단: 단일명령 self-check rc={rc}; 후보를 발행하지 않음")
                return 9
            W.publish_candidate(candidate, source, destination, backup, source_hash)
            candidate = None
            print(f"  작성: {destination}  POU={target.name}; verified replicated command slices={len(target.offsets)}")
            return 0
        except Exception as error:
            print(f"  중단: 단일명령 후보 작성/재검증 실패: {error}")
            return 9
        finally:
            if candidate is not None:
                W.discard_candidate(candidate)
    except Rejected as error:
        print(f"  중단: 단일명령 엄격 검증 실패: {error}")
        return 10
    except Exception as error:
        print(f"  중단: 단일명령 후보 작성 실패: {error}")
        return 9
