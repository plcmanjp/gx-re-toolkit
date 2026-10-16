"""Bounded R object projections, using observed layouts only.

Input: validated archive bytes; SQLite schemas declared in TABLES below.
Output: existing Neutral IR comment/label objects, findings, conserved counts.
Unknown rows keep unique opaque IDs and raw row locators; no PLC/POU/type claim.
"""
from collections import Counter, defaultdict
import hashlib
import json
import sqlite3

from .archive import ArchiveError, sqlite_connection

MAX_ROWS = 100_000
MAX_TEXT = 4_000_000
TABLES = {
    "DEVICE_DATA": ("SEQ", "DevCode", "ExtCode", "ExtNo", "IsLocal", "DevNoHigh", "DevNoLow", "BitNo"),
    "COMMENT_DATA": ("SEQ", "DeviceSEQ", "CmtNo", "CmtData", "DelFlag"),
    "LabelTbl": ("LabelID", "LabelTypeID"),
    "RowTbl": ("LabelID", "RowID", "RowNo", "VarType", "BitCount", "StateFlag", "CheckerState"),
    "ColumnDataTbl": ("LabelID", "RowID", "ColumnID", "ColumnStrValue", "ColumnIntValue"),
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      default=lambda item: {"bytes_hex": item.hex()} if isinstance(item, bytes) else str(item))


class _Reader:
    def __init__(self, archive, name, kind):
        self.name, self.kind = name, kind
        self.digest = archive.digest(name)
        self.items, self.findings, self.states = [], [], []
        self.text_size = 0

    def finding(self, locator, reason):
        self.findings.append({"finding_code": "MINING_REQUIRED", "scope": "project",
                              "object_kind": self.kind, "locator": self.name + ":" + locator if locator != self.name else self.name,
                              "digest": self.digest, "reason": reason})

    def emit(self, locator, raw, *, identity=None, value=None, slot="unknown", partial=False):
        opaque = identity is None
        if opaque:
            # Locator includes physical row ordinal even for duplicate logical keys.
            identity = "MINING_REQUIRED_" + hashlib.sha256((self.name + ":" + locator).encode()).hexdigest()
        evidence = ["bounded observed R storage projection", "raw=" + _json(raw)]
        self.text_size += len(evidence[1]) + (len(value) if isinstance(value, str) else 0)
        if self.text_size > MAX_TEXT:
            raise ArchiveError("R object text budget exceeded")
        if self.kind == "comment":
            evidence.append("common_device is a schema scope placeholder; carrier owner/POU binding is unmined")
        has_text = isinstance(value, str)
        if opaque:
            evidence.append("opaque identity has no decoded object semantics; text, when present, is raw source text")
            if not has_text:
                evidence.append("SLOT_ABSENT is a schema placeholder for undecoded value; not proof of absence")
            if self.kind == "label":
                evidence.append("global_label is a schema placeholder; opaque label scope is unmined")
        self.items.append({"scope": "common_device" if self.kind == "comment" else "global_label" if opaque else "local_label",
                           "program_id": None, "device_id" if self.kind == "comment" else "label_id": identity,
                           "language_slot": slot, "value_state": "SLOT_ABSENT" if not has_text else
                           "EMPTY_STRING" if value == "" else "VALUE_PRESENT", "value": value if has_text else None,
                           "provenance": {"source_entry": self.name, "source_store": locator.split("[", 1)[0],
                                          "source_locator": locator, "source_digest": self.digest,
                                          "relation_evidence": evidence}})
        self.states.append("unknown" if opaque else "partial" if partial else "decoded")


def _rows(db, table):
    # All identifiers are constant allowlisted names, never carrier SQL.
    cursor = db.execute('SELECT * FROM "' + table + '"')
    columns = [column[0] for column in cursor.description]
    rows = cursor.fetchmany(MAX_ROWS + 1)
    if len(rows) > MAX_ROWS:
        raise ArchiveError("R object row budget exceeded")
    if sum(len(value) for row in rows for value in row if isinstance(value, (str, bytes))) > MAX_TEXT:
        raise ArchiveError("R object table text budget exceeded")
    # Stable ordering includes every stored value; exact duplicate rows retain ordinals.
    return columns, sorted((dict(zip(columns, row)) for row in rows), key=_json)


def _device(row):
    keys = TABLES["DEVICE_DATA"]
    if not all(type(row[key]) is int for key in keys):
        return None
    code, ext, number, local, high, low, bit = (row[key] for key in keys[1:])
    if local != 0 or high != 0 or low < 0:
        return None
    if (code, ext, number, bit) == (2, 0, 0, 0):
        return "SM" + str(low)
    if (code, ext, number, low, bit) == (16, 0, 0, 0, 0):
        return "X0"
    prefix = "SD" if (code, ext, number) == (33, 0, 0) else "U3E0\\G" if (code, ext, number) == (35, 208, 992) else None
    return prefix + str(low) + ("." + format(bit - 1, "X") if bit else "") if prefix and 0 <= bit <= 16 else None


def _comments(reader, tables):
    reader.finding(reader.name, "Device identity/text projection only; comment carrier owner and common/program scope binding remain unmined")
    devices = defaultdict(list)
    for index, row in enumerate(tables["DEVICE_DATA"]):
        devices[_json(row["SEQ"])].append((index, row))
    used, candidates = set(), []
    for index, row in enumerate(tables["COMMENT_DATA"]):
        matches = devices.get(_json(row["DeviceSEQ"]), [])
        used.add(_json(row["DeviceSEQ"]))
        device = _device(matches[0][1]) if len(matches) == 1 else None
        slot = {0: "Comment", 6: "English"}.get(row["CmtNo"]) if type(row["CmtNo"]) is int else None
        text = row["CmtData"]
        valid = device is not None and slot is not None and row["DelFlag"] is None and isinstance(text, str)
        candidates.append((index, row, matches, device, slot, valid))
    counts = Counter((device, slot) for _, _, _, device, slot, valid in candidates if valid)
    seqs = Counter(_json(row["SEQ"]) for row in tables["COMMENT_DATA"])
    for index, row, matches, device, slot, valid in candidates:
        locator = f"COMMENT_DATA[{index}];SEQ={_json(row['SEQ'])}"
        valid = valid and counts[(device, slot)] == 1 and seqs[_json(row["SEQ"])] == 1
        raw = {"comment": row, "device": matches[0][1] if len(matches) == 1 else None,
               "device_seq_locator": "DEVICE_DATA[SEQ=" + _json(row["DeviceSEQ"]) + "]",
               "device_match_count": len(matches)}
        if not valid:
            reader.finding(locator, "Unobserved device/slot/delete/text, duplicate identity or orphan comment row; preserved opaque")
        reader.emit(locator, raw, identity=device if valid else None, value=row["CmtData"], slot=slot or "unknown", partial=True)
    for index, row in enumerate(tables["DEVICE_DATA"]):
        if _json(row["SEQ"]) not in used:
            locator = f"DEVICE_DATA[{index}];SEQ={_json(row['SEQ'])}"
            reader.finding(locator, "Orphan device row has no COMMENT_DATA relation")
            reader.emit(locator, row)


def _labels(reader, tables):
    types, rows, cells = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in tables["LabelTbl"]:
        types[_json(row["LabelID"])].append(row)
    for index, row in enumerate(tables["RowTbl"]):
        rows[_json([row["LabelID"], row["RowID"]])].append((index, row))
    for index, row in enumerate(tables["ColumnDataTbl"]):
        cells[_json([row["LabelID"], row["RowID"]])].append((index, row))
    candidates = []
    for key in sorted(set(rows) | set(cells)):
        group, values = rows[key], cells[key]
        sample = group[0][1] if group else values[0][1]
        labels = types.get(_json(sample["LabelID"]), [])
        local = len(labels) == 1 and type(labels[0]["LabelTypeID"]) is int and labels[0]["LabelTypeID"] == 5121
        by_column = defaultdict(list)
        for _, cell in values:
            by_column[_json(cell["ColumnID"])].append(cell)
        name_cells, comment_cells = by_column["2"], by_column["9"]
        # Flags guard two observed storage forms; their semantics remain unmined.
        state_keys = ("VarType", "BitCount", "StateFlag", "CheckerState")
        state = tuple(group[0][1][k] for k in state_keys) if len(group) == 1 else ()
        known_row = (len(group) == 1 and isinstance(sample["LabelID"], str)
                     and type(sample["RowID"]) is int and sample["RowID"] >= 0
                     and tuple(type(v) for v in state) == (int, str, int, int)
                     and state in {(1, "0", 0, 0), (1, "1", 1, 0)})
        name = name_cells[0]["ColumnStrValue"] if len(name_cells) == 1 else None
        comment = comment_cells[0]["ColumnStrValue"] if len(comment_cells) == 1 else None
        known_cells = (len(name_cells) == len(comment_cells) == 1
                       and all(type(cell["ColumnIntValue"]) is int and cell["ColumnIntValue"] == 0
                               for cell in (name_cells[0], comment_cells[0])))
        valid = local and known_row and known_cells and isinstance(name, str) and bool(name) and isinstance(comment, str) and all(len(v) == 1 for v in by_column.values())
        candidates.append((key, group, values, labels, name, comment, valid))
    names = Counter(name for _, _, _, _, name, _, valid in candidates if valid)
    for key, group, values, labels, name, comment, valid in candidates:
        valid = valid and names[name] == 1
        locator = f"RowTbl[LabelID,RowID={key}]"
        if valid:
            raw = {"label_rows": labels, "rows": [row for _, row in group], "cells": [row for _, row in values]}
            reader.finding(locator, "Local name/Comment only; data type, address and POU binding remain unmined")
            reader.emit(locator, raw, identity=name, value=comment, slot="Comment", partial=True)
        else:
            # Each duplicate physical RowTbl row remains represented; column-only
            # orphan groups produce one opaque row identity rather than disappearing.
            for ordinal in range(max(1, len(group))):
                location = locator + f";occurrence={ordinal}"
                reader.finding(location, "Unsupported label type/state/schema, duplicate name/cell/key or orphan row; preserved opaque")
                reader.emit(location, {"row": group[ordinal][1] if group else None,
                                       "observed_name": name, "observed_comment": comment,
                                       "column_group_locator": "ColumnDataTbl[LabelID,RowID=" + key + "]"}, value=comment)
    referenced = {_json(row["LabelID"]) for row in tables["RowTbl"] + tables["ColumnDataTbl"]}
    for index, row in enumerate(tables["LabelTbl"]):
        if _json(row["LabelID"]) not in referenced:
            reader.finding(f"LabelTbl[{index}]", "Label metadata has no actual RowTbl/ColumnDataTbl object row")


def read_objects(archive, kind):
    """Existing parser adapter: unknown carrier/schema stays explicit, not absent."""
    if kind not in {"comment", "label"}:
        raise ValueError("unknown R object kind")
    names = sorted(name for name in archive.entries if name.endswith("_DC.db")) if kind == "comment" else sorted(name for name in archive.entries if name == "LabelData.db")
    items, findings, states, text_size = [], [], [], 0
    required = ("DEVICE_DATA", "COMMENT_DATA") if kind == "comment" else ("LabelTbl", "RowTbl", "ColumnDataTbl")
    for name in names:
        reader = _Reader(archive, name, kind)
        db = sqlite_connection(archive.entries[name])
        try:
            tables, valid = {}, True
            present = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in required:
                if table not in present:
                    reader.finding(table, "Required object table absent")
                    valid = False
                    continue
                columns, tables[table] = _rows(db, table)
                if set(TABLES[table]) != set(columns):
                    reader.finding(table, "Object table schema is unmined")
                    valid = False
            if sum(map(len, tables.values())) > MAX_ROWS:
                raise ArchiveError("R object carrier row budget exceeded")
            if valid:
                (_comments if kind == "comment" else _labels)(reader, tables)
            else:
                for table in required:
                    for index, row in enumerate(tables.get(table, [])):
                        reader.emit(f"{table}[{index}]", row, value=row.get("CmtData") if kind == "comment" else row.get("ColumnStrValue"))
        except sqlite3.Error as error:
            # A failed read must not be presented as an empty successful carrier.
            raise ArchiveError("R object carrier query failed") from error
        finally:
            db.close()
        if len(items) + len(reader.items) > MAX_ROWS:
            raise ArchiveError("R object output row budget exceeded")
        text_size += reader.text_size
        if text_size > MAX_TEXT:
            raise ArchiveError("R object output text budget exceeded")
        items.extend(reader.items); findings.extend(reader.findings); states.extend(reader.states)
    if not names:
        findings.append({"finding_code": "MINING_REQUIRED", "scope": "project", "object_kind": kind,
                         "locator": "project", "digest": archive.input_sha256,
                         "reason": "Object carrier absent or unmined"})
    identifier = "device_id" if kind == "comment" else "label_id"
    # Cross-carrier duplicate semantic identities must not violate Neutral IR keys.
    identities = Counter((row["scope"], row[identifier], row["language_slot"]) for row in items)
    for index, row in enumerate(items):
        if identities[(row["scope"], row[identifier], row["language_slot"])] > 1:
            row["provenance"]["relation_evidence"].append("unbound_duplicate_identity=" + row[identifier])
            row[identifier] = "MINING_REQUIRED_" + hashlib.sha256(_json(row["provenance"]).encode()).hexdigest()
            states[index] = "unknown"
            findings.append({"finding_code": "MINING_REQUIRED", "scope": "project", "object_kind": kind,
                             "locator": row["provenance"]["source_entry"] + ":" + row["provenance"]["source_locator"], "digest": row["provenance"]["source_digest"],
                             "reason": "Duplicate semantic identity across carriers; preserved opaque"})
    items.sort(key=lambda row: (row["scope"], row["program_id"] or "", row[identifier], row["language_slot"]))
    return items, findings, {"total": len(items), "decoded": states.count("decoded"),
                            "partial": states.count("partial"), "unknown": states.count("unknown")}
