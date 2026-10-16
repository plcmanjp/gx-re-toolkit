"""Read-only supplemental R label details; does not modify Neutral IR.

Input schema: LabelTbl, RowTbl and ColumnDataTbl from objects.TABLES.
Output schema: plcman.gx3.r-label-details v1, documented in the boundary note.
Dependencies: standard library and this package. No writer or CLI is provided.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3

from . import parser
from .archive import ArchiveError, SafeGx3Archive, sha256_file, sqlite_connection
from .objects import MAX_ROWS, MAX_TEXT, TABLES

LABEL_TABLES = ("LabelTbl", "RowTbl", "ColumnDataTbl")
# Official export order, using stable language-independent keys.
ATTRIBUTE_KEYS = (
    "class", "label_name", "data_type", "constant", "initial_value", "assign",
    "address", "comment", "comment2", "comment3", "comment4", "comment5",
    "japanese", "english", "chinese_simplified", "korean", "chinese_traditional",
    "german", "italian", "reserved1", "reserved2", "reserved3", "reserved4",
    "remark", "system_label_relation", "system_label_name", "attribute",
)


def _raw(value):
    """Keep SQLite scalars JSON-safe without pretending blobs/reals are text."""
    if isinstance(value, bytes):
        return {"storage_type": "blob", "hex": value.hex()}
    if type(value) is float:
        return {"storage_type": "real", "hex": value.hex()}
    return value


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _key(value):
    if isinstance(value, list):
        return _json([_raw(item) for item in value])
    return _json(_raw(value))


def _load_tables(db):
    tables, raw_tables, findings = {}, {}, []
    present = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN "
                              "('LabelTbl','RowTbl','ColumnDataTbl')"))
    valid, row_count, text_count = True, 0, 0
    for name in LABEL_TABLES:
        if present.get(name) != "table":
            valid = False
            findings.append({"code": "UNKNOWN_SCHEMA", "locator": name,
                             "reason": "Required real table absent; views are not read"})
            continue
        cursor = db.execute('SELECT * FROM "' + name + '"')
        columns = [column[0] for column in cursor.description]
        rows = []
        while True:
            batch = cursor.fetchmany(min(256, MAX_ROWS + 1))
            if not batch:
                break
            row_count += len(batch)
            if row_count > MAX_ROWS:
                raise ArchiveError("R label details row budget exceeded")
            text_count += sum(len(item) for row in batch for item in row
                              if isinstance(item, (str, bytes)))
            if text_count > MAX_TEXT:
                raise ArchiveError("R label details text budget exceeded")
            rows.extend(dict(zip(columns, row)) for row in batch)
        rows.sort(key=lambda row: _json({key: _raw(value) for key, value in row.items()}))
        tables[name] = rows
        raw_tables[name] = {"columns": columns, "rows": [
            {key: _raw(value) for key, value in row.items()} for row in rows]}
        if set(columns) != set(TABLES[name]):
            valid = False
            findings.append({"code": "UNKNOWN_SCHEMA", "locator": name,
                             "reason": "Unobserved table columns; raw rows preserved"})
    return tables, raw_tables, valid, findings


def _observed_cell(cells, text, integer):
    return (len(cells) == 1 and type(cells[0][1]["ColumnStrValue"]) is str
            and cells[0][1]["ColumnStrValue"] == text
            and type(cells[0][1]["ColumnIntValue"]) is int
            and cells[0][1]["ColumnIntValue"] == integer)


def _records(tables, schema_valid, digest):
    records = []
    output_text = 0

    def emit(kind, label_id, row_id, occurrence, refs, values=None):
        nonlocal output_text
        locator = _json([kind, _raw(label_id), _raw(row_id), occurrence, refs])
        attributes = {key: {"status": "UNKNOWN", "value": None} for key in ATTRIBUTE_KEYS}
        for key, value in (values or {}).items():
            attributes[key] = {"status": "SUPPORTED", "value": value}
        record = {
            "record_id": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
            "kind": kind, "status": "PARTIAL" if values else "UNKNOWN",
            "storage_key": {"label_id": _raw(label_id), "row_id": _raw(row_id)},
            "occurrence": occurrence, "source_rows": refs,
            "owner": {"status": "UNKNOWN", "pou_id": None},
            "attributes": attributes,
            "provenance": {"source_entry": "LabelData.db", "source_digest": digest,
                           "source_locator": locator},
        }
        output_text += len(_json(record))
        if output_text > MAX_TEXT:
            raise ArchiveError("R label details output text budget exceeded")
        if len(records) >= MAX_ROWS:
            raise ArchiveError("R label details output row budget exceeded")
        records.append(record)

    if not schema_valid:
        for name in LABEL_TABLES:
            for index, row in enumerate(tables.get(name, [])):
                emit("unmapped_storage_row", row.get("LabelID"), row.get("RowID"), index,
                     {table: [index] if table == name else [] for table in LABEL_TABLES})
        return records

    types, rows, cells = defaultdict(list), defaultdict(list), defaultdict(list)
    for index, row in enumerate(tables["LabelTbl"]):
        types[_key(row["LabelID"])].append((index, row))
    for index, row in enumerate(tables["RowTbl"]):
        rows[_key([row["LabelID"], row["RowID"]])].append((index, row))
    for index, cell in enumerate(tables["ColumnDataTbl"]):
        cells[_key([cell["LabelID"], cell["RowID"]])].append((index, cell))
    candidates = []
    for key in sorted(set(rows) | set(cells)):
        group, values = rows[key], cells[key]
        sample = (group or values)[0][1]
        labels = types.get(_key(sample["LabelID"]), [])
        by_column = defaultdict(list)
        for index, cell in values:
            by_column[_key(cell["ColumnID"])].append((index, cell))
        name_cells, comment_cells = by_column["2"], by_column["9"]
        name = name_cells[0][1]["ColumnStrValue"] if len(name_cells) == 1 else None
        comment = comment_cells[0][1]["ColumnStrValue"] if len(comment_cells) == 1 else None
        state = tuple(group[0][1][k] for k in ("VarType", "BitCount", "StateFlag", "CheckerState")) if len(group) == 1 else ()
        valid = (
            len(labels) == 1 and type(labels[0][1]["LabelTypeID"]) is int
            and labels[0][1]["LabelTypeID"] == 5121
            and len(group) == 1 and type(sample["LabelID"]) is str
            and type(sample["RowID"]) is int and sample["RowID"] >= 0
            and tuple(type(value) for value in state) == (int, str, int, int)
            and state in {(1, "0", 0, 0), (1, "1", 1, 0)}
            and type(name) is str and bool(name) and type(comment) is str
            and len(name_cells) == len(comment_cells) == 1
            and all(type(cell[1]["ColumnIntValue"]) is int
                    and cell[1]["ColumnIntValue"] == 0
                    for cell in name_cells + comment_cells)
            and all(type(cell["ColumnID"]) is int and cell["ColumnID"] in {1, 2, 3, 9}
                    for _, cell in values)
            and all(len(value) == 1 for value in by_column.values())
        )
        candidates.append((group, values, labels, sample, by_column, name, comment, valid))
    # Match the existing reader's duplicate semantic-name guard. Count identities
    # before the stronger supplemental column guard, so unknown extra attributes
    # cannot rescue an otherwise colliding name.
    names = Counter()
    for group, values, labels, sample, by_column, name, comment, valid in candidates:
        if (len(labels) == len(group) == 1 and type(labels[0][1]["LabelTypeID"]) is int
                and labels[0][1]["LabelTypeID"] == 5121
                and type(name) is str and name):
            names[name] += 1
    for group, values, labels, sample, by_column, name, comment, valid in candidates:
        supported = {}
        if valid and names[name] == 1:
            supported = {"label_name": name, "comment": comment}
            if _observed_cell(by_column["1"], "VAR", 4):
                supported["class"] = "VAR"
            if _observed_cell(by_column["3"], "", 1):
                supported["data_type"] = "BOOL"
        for occurrence in range(max(1, len(group))):
            emit("label_row" if group else "orphan_cells", sample["LabelID"], sample["RowID"], occurrence,
                 {"LabelTbl": [index for index, _ in labels],
                  "RowTbl": [group[occurrence][0]] if group else [],
                  "ColumnDataTbl": [index for index, _ in values]}, supported)
    referenced = {_key(row["LabelID"]) for row in tables["RowTbl"] + tables["ColumnDataTbl"]}
    for index, row in enumerate(tables["LabelTbl"]):
        if _key(row["LabelID"]) not in referenced:
            emit("label_metadata", row["LabelID"], None, index,
                 {"LabelTbl": [index], "RowTbl": [], "ColumnDataTbl": []})
    return records


def parse_label_details(path):
    """Return supplementary observed attributes, or raise ArchiveError.

    Always run the production R parser first, then require the same input digest
    for a fresh bounded archive read. Unknown values are never empty-value claims.
    """
    source = Path(path)
    base = parser.parse(source)
    if base.get("status") == "FATAL":
        raise ArchiveError("R parser rejected the label details input")
    parser.validate_ir(base)
    if (base["profile"]["detector_status"] != "SUPPORTED"
            or base["input"]["read_only_unchanged"] is not True):
        raise ArchiveError("R04 profile or unchanged-input gate is not satisfied")
    archive = SafeGx3Archive(source)
    if archive.input_sha256 != base["input"]["sha256"]:
        raise ArchiveError("input changed between parser and label details reads")
    findings = [{"code": "PARTIAL_SCOPE", "locator": "project",
                 "reason": "Supplemental attributes only; owner, full attributes and project completeness remain unknown"}]
    tables, raw_tables, records = {}, {}, []
    carrier = None
    if "LabelData.db" in archive.entries:
        digest = archive.digest("LabelData.db")
        carrier = {"entry": "LabelData.db", "sha256": digest}
        db = sqlite_connection(archive.entries["LabelData.db"])
        try:
            tables, raw_tables, valid, local_findings = _load_tables(db)
            records = _records(tables, valid, digest)
            findings.extend(local_findings)
        except sqlite3.Error as error:
            raise ArchiveError("R label details SQLite query failed") from error
        finally:
            db.close()
    else:
        findings.append({"code": "UNKNOWN_CARRIER", "locator": "LabelData.db",
                         "reason": "Carrier absent; no claim of label absence"})
    partial = sum(record["status"] == "PARTIAL" for record in records)
    for record in records:
        if record["status"] == "UNKNOWN":
            findings.append({"code": "UNKNOWN_LABEL", "locator": record["record_id"],
                             "reason": "Unobserved type, state, cells, schema or identity; raw rows preserved"})
    result = {
        "schema_name": "plcman.gx3.r-label-details", "schema_version": "1.0.0",
        "status": "PARTIAL" if partial else "UNKNOWN", "project_complete": False,
        "input": dict(base["input"]),
        "profile": {key: base["profile"][key] for key in ("profile_id", "detector_status")},
        "source": carrier, "records": records, "raw_tables": raw_tables,
        "findings": findings,
        "counts": {"total": len(records), "partial": partial, "unknown": len(records) - partial},
    }
    if len(_json(result)) > MAX_TEXT:
        raise ArchiveError("R label details output text budget exceeded")
    if archive.input_sha256 != sha256_file(source):
        raise ArchiveError("input changed during label details read")
    return result
