"""Closed R04 LDDB source path for a schema-valid, exactly empty MIL.

Input: immutable archive entries; T_Block(Pos,BlockID,StepSize,BodyID),
T_Step(Pos,ElementIDMacroFB,BlockID,MilID,StepSize), LadderBlocks(id,pos,
blocktype,data), MIL(id,pos,data). Output: existing Neutral IR records only.
Exactly one two-cell M contact/coil block and one final END are observed.
All validation precedes record construction; unknown forms yield no records.
"""
from contextlib import closing
import math
import re
import sqlite3

from .archive import ArchiveError, sqlite_connection

MAX_ROWS = 10_000
END = "V1:0:end{type=end:dim=1x1}"
CONTACT = re.compile(
    r"V1:4:1:1:1:1:(?P<contact>a|b):M:c:M:"
    + re.escape("cb{fg=fg{dim=2x1:es=[e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=")
    + r"(?P<source>[0-9]{1,10})"
    + re.escape(":vt=nn}]}:pos=0,0}:e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=")
    + r"(?P<target>[0-9]{1,10})"
    + re.escape(":vt=nn}]}:pos=1,0}]}}")
)


class LddbSourceError(ValueError):
    def __init__(self, code, locator, source_entry):
        self.code, self.locator, self.source_entry = code, locator, source_entry
        super().__init__(code)


def _require(condition, code, locator, source_entry):
    if not condition:
        raise LddbSourceError(code, locator, source_entry)


def _key(value, locator, source_entry):
    _require(isinstance(value, str) and bool(value) and len(value) <= 512, "LDDB_BLOCK_ID_UNVERIFIED", locator, source_entry)
    key = value.removeprefix("_guid/").strip("{}").casefold()
    _require(bool(key), "LDDB_BLOCK_ID_UNVERIFIED", locator, source_entry)
    return key


def _pos(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _read(archive, name, table, columns, *, first_only=False):
    locator = name + ":" + table
    try:
        with closing(sqlite_connection(archive.entries[name])) as db:
            definition = db.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
            _require(definition == ("table",), "LDDB_SOURCE_NOT_TABLE", locator, name)
            available = {row[1] for row in db.execute('PRAGMA table_info("' + table + '")')}
            _require(set(columns).issubset(available), "LDDB_SOURCE_SCHEMA_UNVERIFIED", locator, name)
            rows = db.execute('SELECT ' + ','.join('"' + col + '"' for col in columns) +
                              ' FROM "' + table + '"').fetchmany(1 if first_only else MAX_ROWS + 1)
            _require(first_only or len(rows) <= MAX_ROWS, "LDDB_SOURCE_ROW_LIMIT", locator, name)
            return rows
    except (sqlite3.Error, ArchiveError, KeyError) as exc:
        raise LddbSourceError("LDDB_SOURCE_CARRIER_UNREADABLE", locator, name) from exc


def mil_is_empty(archive, mil_name):
    """One-row probe before any full StepInfo/LDDB/MIL materialization."""
    return not _read(archive, mil_name, "MIL", ("id", "pos", "data"), first_only=True)


def decode_empty_mil(archive, pou, lddb_name, mil_name):
    """Return transactional records, or a precise source/row rejection."""
    step_name = pou["stepinfo"]
    mil = _read(archive, mil_name, "MIL", ("id", "pos", "data"))
    _require(not mil, "LDDB_FALLBACK_REQUIRES_EMPTY_MIL", mil_name + ":MIL", mil_name)
    blocks = _read(archive, step_name, "T_Block", ("Pos", "BlockID", "StepSize", "BodyID"))
    steps = _read(archive, step_name, "T_Step", ("Pos", "ElementIDMacroFB", "BlockID", "MilID", "StepSize"))
    ladder = _read(archive, lddb_name, "LadderBlocks", ("id", "pos", "blocktype", "data"))
    _require(len(blocks) == len(ladder) == 2, "LDDB_TWO_BLOCK_FORM_UNVERIFIED", lddb_name + ":LadderBlocks", lddb_name)
    block_map, ladder_map, raw_ids = {}, {}, {}
    for pos, block_id, size, body in blocks:
        locator = step_name + ":T_Block[BlockID=" + str(block_id) + "]"
        key = _key(block_id, locator, step_name)
        _require(key not in block_map, "LDDB_DUPLICATE_BLOCK_ID", locator, step_name)
        _require(_pos(pos) and type(size) is int and size == 2 and type(body) is int and body >= 0,
                 "LDDB_BLOCK_FIELDS_UNVERIFIED", locator, step_name)
        block_map[key] = (pos, size, body)
    _require(len({row[0] for row in block_map.values()}) == 2, "LDDB_BLOCK_ORDER_UNVERIFIED", step_name + ":T_Block", step_name)
    _require(len({row[2] for row in block_map.values()}) == 1, "LDDB_MULTIPLE_BODIES_UNVERIFIED", step_name + ":T_Block", step_name)
    for block_id, pos, kind, data in ladder:
        locator = lddb_name + ":LadderBlocks[id=" + str(block_id) + "]"
        key = _key(block_id, locator, lddb_name)
        _require(key not in ladder_map, "LDDB_DUPLICATE_BLOCK_ID", locator, lddb_name)
        _require(_pos(pos) and type(kind) is int and isinstance(data, str) and len(data) <= 1024,
                 "LDDB_LADDER_FIELDS_UNVERIFIED", locator, lddb_name)
        ladder_map[key] = (pos, kind, data)
        raw_ids[key] = block_id
    _require(set(ladder_map) == set(block_map), "LDDB_BLOCK_BIJECTION_FAILED", lddb_name + ":LadderBlocks", lddb_name)
    ordered = sorted(block_map, key=lambda key: block_map[key][0])
    step_map = {key: {} for key in block_map}
    for pos, element, block_id, mil_id, size in steps:
        locator = step_name + ":T_Step[BlockID=" + str(block_id) + ",MilID=" + str(mil_id) + "]"
        key = _key(block_id, locator, step_name)
        _require(key in block_map and _pos(pos) and pos == block_map[key][0] and
                 type(element) is int and element == 0 and type(mil_id) is int and mil_id >= 0 and
                 type(size) is int and size > 0, "LDDB_STEP_FIELDS_UNVERIFIED", locator, step_name)
        _require(mil_id not in step_map[key], "LDDB_DUPLICATE_STEP_ID", locator, step_name)
        step_map[key][mil_id] = size
    decoded = []
    for order, key in enumerate(ordered):
        locator = lddb_name + ":LadderBlocks[id=" + raw_ids[key] + "]"
        pos, kind, data = ladder_map[key]
        _require(pos == block_map[key][0], "LDDB_POSITION_MISMATCH", locator, lddb_name)
        expected = {0: 1, 1: 1} if order == 0 else {0: 2}
        _require(step_map[key] == expected and sum(step_map[key].values()) == block_map[key][1],
                 "LDDB_STEP_SIZE_OR_ORDER_MISMATCH", step_name + ":T_Step[BlockID=" + key + "]", step_name)
        if order == 1:
            _require(kind == 5 and data == END, "LDDB_FINAL_END_UNVERIFIED", locator, lddb_name)
            instructions = [("END", None, 2)]
        else:
            match = CONTACT.fullmatch(data)
            _require(kind == 0 and match is not None, "LDDB_CONTACT_COIL_GRAMMAR_UNVERIFIED", locator, lddb_name)
            source, target = int(match["source"]), int(match["target"])
            _require(max(source, target) <= 0xFFFFFFFF, "LDDB_M_ADDRESS_OUTSIDE_U32", locator, lddb_name)
            instructions = [("LD" if match["contact"] == "a" else "LDI", "M" + str(source), 1),
                            ("OUT", "M" + str(target), 1)]
        decoded.append((key, instructions))
    records, current_step = [], 0
    lddb_digest, mil_digest, step_digest = archive.digest(lddb_name), archive.digest(mil_name), archive.digest(step_name)
    for key, instructions in decoded:
        locator = f"pou:{pou['pou_id']}/{lddb_name}:LadderBlocks[id={raw_ids[key]}]"
        for mil_id, (opcode, token, size) in enumerate(instructions):
            provenance = {"source_entry": lddb_name, "source_store": "LadderBlocks",
                          "source_locator": locator + f"/instruction:{mil_id}", "source_digest": lddb_digest,
                          "relation_evidence": ["read_source=LDDB; closed two-block observed grammar",
                              "empty_MIL=" + mil_name + ";sha256=" + mil_digest,
                              "StepInfo=" + step_name + ";sha256=" + step_digest + f";block={key};MilID={mil_id};StepSize={size}",
                              "native/PLC/program completeness not established"]}
            operands = [] if token is None else [{"position": 0, "raw_token": token, "kind": "device",
                "value": token[1:], "width": None, "indirection": None, "index": None, "provenance": provenance}]
            records.append({"record_id": f"{pou['pou_id']}:{len(records)}", "sequence": len(records),
                            "kind": "instruction", "step": current_step, "opcode": opcode, "operands": operands,
                            "text": None, "status": "decoded", "continues_record_id": None, "provenance": provenance})
            current_step += size
    return records
