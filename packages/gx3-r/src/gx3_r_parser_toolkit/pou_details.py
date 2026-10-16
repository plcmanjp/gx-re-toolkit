"""Bounded supplemental observations of rooted R binary QPG directories.

Input: production-parser-validated R04 archive, binary QPG directory forms below.
Output: separate plcman.gx3.r-pou-details v1 dictionary; no Neutral IR changes.
Dependencies: standard library and this package. No writer, GUI, network or CLI.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct

from . import parser
from .archive import ArchiveError, SafeGx3Archive, sha256_file

MAX_CARRIERS = 256
MAX_QPG_BYTES = 8 * 1024 * 1024
MAX_TOTAL_QPG_BYTES = 32 * 1024 * 1024
MAX_LINK_BYTES = 4096
MAX_DIRECTORY_ENTRIES = 32
MAX_TAIL_COUNT = 100_000
MAX_OUTPUT_TEXT = 4_000_000
SHORT_FIELDS = ((4, 12, 1), (16, 4, 0x102), (20, 8, 3), (28, 68, 4),
                (96, 72, 0x205), (168, 36, 6), (204, 308, 7))
NAMED_TAGS = (0, 1, 3, 5, 6, 8, 0x10000, 0x10002, 0x10004, 0x10006, 0x10007)
UNNAMED_TAGS = (0, 1, 3, 4, 5, 6, 7, 0x10000, 0x10002, 0x10006, 0x10007)
NAME_TAG = 0x10006


class _UnknownLayout(ValueError):
    pass


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _require(condition, reason):
    if not condition:
        raise _UnknownLayout(reason)


def _directory(data):
    """Follow root fields and indexed ranges, never search payload for names."""
    _require(len(data) >= 528, "Root header is truncated")
    _require(struct.unpack_from("<I", data)[0] == 0x02040080, "Unobserved root identifier")
    cursor = 4
    for offset, size, tag in SHORT_FIELDS:
        _require(cursor == offset and struct.unpack_from("<HH", data, cursor) == (size, tag),
                 "Unobserved short-field framing")
        cursor += size
    _require(cursor == 512 and struct.unpack_from("<I", data, cursor)[0] == 0xFFFFFFFF,
             "Extended directory marker is absent")
    base = cursor + 4
    length = struct.unpack_from("<I", data, base)[0]
    counts = struct.unpack_from("<HH", data, base + 4)
    count = sum(counts)
    _require(count <= MAX_DIRECTORY_ENTRIES, "Directory count budget exceeded")
    _require(counts in {(6, 5), (7, 4)}, "Unobserved directory counts")
    expected = NAMED_TAGS if counts == (6, 5) else UNNAMED_TAGS
    table_end = 8 + count * 12
    root_tail, whole_length = struct.unpack_from("<II", data, 8)
    extended_end = base + length
    _require(length >= table_end + 8 and extended_end + 8 + 12 <= len(data),
             "Extended directory exceeds carrier bounds")
    _require(root_tail == extended_end + 8 and whole_length == len(data),
             "Root length or tail offset differs from framing")
    _require(data[extended_end:root_tail] == struct.pack("<II", 0x2FD00000, 0),
             "Unobserved root separator")
    _require(data[extended_end - 8:extended_end] == data[root_tail:root_tail + 8],
             "Root trailer identity mirror differs")
    tail_count = struct.unpack_from("<I", data, root_tail + 8)[0]
    _require(tail_count <= MAX_TAIL_COUNT, "Opaque tail count budget exceeded")
    entries, ranges, seen = [], [], set()
    for ordinal in range(count):
        tag, offset, size = struct.unpack_from("<III", data, base + 8 + 12 * ordinal)
        _require(tag not in seen, "Duplicate directory tag")
        seen.add(tag)
        _require(tag == expected[ordinal], "Unobserved directory tag order")
        _require((offset == 0) == (size == 0), "Partial zero directory range")
        if size:
            _require(table_end <= offset and size <= length - 8
                     and offset <= length - 8 - size, "Directory payload range is outside its envelope")
            ranges.append((offset, offset + size))
        entries.append({"tag": tag, "relative_offset": offset,
                        "absolute_offset": base + offset if size else None,
                        "byte_count": size,
                        "sha256": _digest(memoryview(data)[base + offset:base + offset + size]) if size else None})
    position = table_end
    for start, end in ranges:
        _require(start == position, "Directory payloads overlap, have gaps or are out of order")
        position = end
    _require(position == length - 8, "Directory payloads do not cover the declared envelope")
    by_tag = {entry["tag"]: entry for entry in entries}
    fixed = {0: 4, 1: 8, 3: 8, 5: 0, 6: 0, 0x10007: 236}
    if counts == (6, 5):
        fixed.update({8: 12, 0x10004: 184})
        for tag in (0x10000, 0x10002):
            size = by_tag[tag]["byte_count"]
            _require(size >= 12 and size % 4 == 0, "Unobserved opaque-section size framing")
    else:
        fixed.update({4: 12, 7: 8, 0x10000: 72, 0x10002: 88, NAME_TAG: 0})
    _require(all(by_tag[tag]["byte_count"] == size for tag, size in fixed.items()),
             "Unobserved fixed directory field length")
    name_entry = by_tag[NAME_TAG]
    observed_name = None
    name_state = "ZERO_LENGTH"
    if counts == (6, 5):
        size, start = name_entry["byte_count"], name_entry["absolute_offset"]
        _require(size >= 40 and start is not None, "Named form has no bounded name field")
        byte_length = struct.unpack_from("<H", data, start)[0]
        _require(4 <= byte_length <= 130 and byte_length % 2 == 0
                 and size == byte_length + 36, "Name length differs from its directory field")
        end = start + 2 + byte_length
        payload = data[start + 2:end]
        _require(payload[-2:] == bytes(2), "Name lacks its terminator")
        try:
            observed_name = payload[:-2].decode("utf-16le", errors="strict")
        except UnicodeDecodeError as error:
            raise _UnknownLayout("Name is not strict UTF-16LE") from error
        _require(1 <= len(observed_name) <= 64 and observed_name.isidentifier()
                 and all(character.isprintable() for character in observed_name),
                 "Name is not an unambiguous identifier")
        _require(data[end:start + size] == bytes(32) + struct.pack("<H", 0x100),
                 "Unobserved name padding or terminal tag")
        name_state = "PRESENT"
    framing = {"directory_counts": list(counts), "directory_base": base,
               "extended_length": length, "root_tail_offset": root_tail,
               "whole_length": whole_length,
               "opaque_tail": {"byte_count": len(data) - root_tail,
                               "observed_count": tail_count,
                               "sha256": _digest(memoryview(data)[root_tail:]),
                               "interpretation": "UNKNOWN"}}
    return framing, entries, name_state, observed_name


def _links(archive):
    paths = sorted(name for name in archive.entries
                   if PurePosixPath(name).name.casefold() == "poulinkorder.info")
    if len(paths) > MAX_CARRIERS:
        raise ArchiveError("R POU details link census budget exceeded")
    inventory = []
    for name in paths:
        data = archive.entries[name]
        if len(data) > MAX_LINK_BYTES:
            raise ArchiveError("R POU details link text budget exceeded")
        item = {"source_entry": name, "sha256": _digest(data), "byte_count": len(data),
                "status": "INVALID", "ids": []}
        try:
            lines = data.decode("ascii", errors="strict").splitlines()
        except UnicodeDecodeError:
            inventory.append(item)
            continue
        # Match only the observed ASCII decimal, one-ID-per-line storage form.
        if lines and all(line and line.isdecimal() for line in lines):
            item["ids"] = lines
            item["status"] = "SINGLETON" if len(lines) == 1 else "AMBIGUOUS"
        inventory.append(item)
    identities = Counter(identifier for item in inventory for identifier in item["ids"])
    for item in inventory:
        if any(identities[identifier] != 1 for identifier in item["ids"]):
            item["status"] = "AMBIGUOUS"
    return inventory


def parse_pou_details(path):
    """Observe QPG fields without claiming semantic POU ownership or binding."""
    source = Path(path)
    base = parser.parse(source)
    if base.get("status") == "FATAL":
        raise ArchiveError("R parser rejected the POU details input")
    parser.validate_ir(base)
    if (base["profile"]["detector_status"] != "SUPPORTED"
            or base["input"]["read_only_unchanged"] is not True):
        raise ArchiveError("R04 profile or unchanged-input gate is not satisfied")
    archive = SafeGx3Archive(source)
    if archive.input_sha256 != base["input"]["sha256"]:
        raise ArchiveError("input changed between parser and POU details reads")
    names = sorted(name for name in archive.entries if PurePosixPath(name).suffix.casefold() == ".qpg")
    if len(names) > MAX_CARRIERS:
        raise ArchiveError("R POU details carrier census budget exceeded")
    if sum(len(archive.entries[name]) for name in names) > MAX_TOTAL_QPG_BYTES:
        raise ArchiveError("R POU details aggregate byte budget exceeded")
    links = _links(archive)
    link_positions = {item["source_entry"]: index for index, item in enumerate(links)}
    parent_counts = Counter(str(PurePosixPath(name).parent) for name in names)
    records, findings, linked = [], [], set()
    for name in names:
        data = archive.entries[name]
        if len(data) > MAX_QPG_BYTES:
            raise ArchiveError("R POU details carrier byte budget exceeded")
        link_path = str(PurePosixPath(name).parent / "PouLinkOrder.info")
        link_index = link_positions.get(link_path)
        if link_index is not None:
            linked.add(link_index)
        record = {"source_entry": name, "source_digest": _digest(data), "byte_count": len(data),
                  "status": "UNKNOWN", "layout_status": "UNKNOWN",
                  "root_framing": None, "directory": [], "name_field_state": "UNKNOWN",
                  "observed_name": {"status": "UNKNOWN", "value": None},
                  "link_inventory_index": link_index,
                  "semantic_owner": {"status": "UNKNOWN", "value": None},
                  "pou_binding": {"status": "UNKNOWN", "pou_id": None}, "findings": []}
        try:
            _require(PurePosixPath(name).name == "Program.qpg", "Unobserved QPG filename")
            framing, directory, state, candidate = _directory(data)
            record.update(status="PARTIAL", layout_status="OBSERVED_FORM", root_framing=framing,
                          directory=directory, name_field_state=state)
            if candidate is not None:
                if (link_index is not None and links[link_index]["status"] == "SINGLETON"
                        and parent_counts[str(PurePosixPath(name).parent)] == 1):
                    record["observed_name"] = {"status": "OBSERVED", "value": candidate}
                else:
                    record["findings"].append({"code": "AMBIGUOUS_NAME_CONTEXT",
                                               "reason": "Name withheld without a unique singleton link observation"})
        except _UnknownLayout as error:
            record["findings"].append({"code": "UNKNOWN_LAYOUT", "reason": str(error)})
        if link_index is None:
            record["findings"].append({"code": "UNLINKED_CARRIER", "reason": "No same-parent link carrier"})
        records.append(record)
    for index, link in enumerate(links):
        if index not in linked:
            findings.append({"code": "UNMATCHED_LINK", "locator": link["source_entry"],
                             "reason": "Link has no exact same-parent QPG carrier"})
    if not names:
        findings.append({"code": "UNKNOWN_CARRIER", "locator": "project",
                         "reason": "No QPG carrier observed; not proof of POU absence"})
    findings.append({"code": "PARTIAL_SCOPE", "locator": "project",
                     "reason": "Storage observations only; semantic owner, POU binding and project completeness remain unknown"})
    partial = sum(record["status"] == "PARTIAL" for record in records)
    result = {"schema_name": "plcman.gx3.r-pou-details", "schema_version": "1.0.0",
              "status": "PARTIAL" if partial else "UNKNOWN", "project_complete": False,
              "input": dict(base["input"]),
              "profile": {key: base["profile"][key] for key in ("profile_id", "detector_status")},
              "records": records, "link_inventory": links,
              "counts": {"total": len(records), "partial": partial, "unknown": len(records) - partial},
              "findings": findings}
    if len(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False)) > MAX_OUTPUT_TEXT:
        raise ArchiveError("R POU details output text budget exceeded")
    if archive.input_sha256 != sha256_file(source):
        raise ArchiveError("input changed during POU details read")
    return result
