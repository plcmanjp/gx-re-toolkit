"""Bounded Explorer/Diff for pinned GXW reference IR and GX3 Neutral IR.

The tool preserves order, duplicate identities, provenance, unknown states and
comment value states.  It is read-only research output, not an editor or an
official GX equivalence decision.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from . import coverage_ledger as safe
from . import reference_query as reference

REPORT_FORMAT = "plcman.gx-re-lab.explorer-diff"
MAX_OBJECTS = 100_000
MAX_EVENTS = 10_000
NEUTRAL_ROOT_FIELDS = {"schema_name", "schema_version", "producer", "input", "profile", "project",
                       "pous", "comments", "labels", "findings", "coverage"}
PROVENANCE_FIELDS = {"source_entry", "source_store", "source_locator", "source_digest",
                     "relation_evidence"}
POU_FIELDS = {"pou_id", "name", "language", "execution_order", "program_kind", "relations", "records",
              "findings"}
RECORD_FIELDS = {"record_id", "sequence", "kind", "step", "opcode", "operands", "text", "provenance",
                 "status", "continues_record_id"}
OPERAND_FIELDS = {"position", "raw_token", "kind", "value", "width", "indirection", "index", "provenance"}
FINDING_FIELDS = {"finding_code", "scope", "object_kind", "locator", "digest", "reason"}


class ExplorerDiffError(safe.LedgerError):
    pass


def _fail(condition: bool, code: str = "EXPLORER_DIFF_SCHEMA") -> None:
    if not condition:
        raise ExplorerDiffError(code)


def _key(*parts: object) -> str:
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":"))


def _duplicates(values: Iterable[str]) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def _reject_surrogates(value: Any) -> None:
    if isinstance(value, str):
        _fail(not any(0xD800 <= ord(character) <= 0xDFFF for character in value),
              "EXPLORER_SURROGATE")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_surrogates(key)
            _reject_surrogates(item)
    elif isinstance(value, list):
        for item in value:
            _reject_surrogates(item)


def _neutral_source_state(source: dict[str, Any]) -> str:
    coverage = source.get("coverage")
    if not isinstance(coverage, dict):
        return "UNKNOWN"
    if set(coverage) != {"project", "pou", "record", "comment", "label"}:
        return "UNKNOWN"
    profile = source.get("profile")
    if not isinstance(profile, dict) or profile.get("detector_status") != "SUPPORTED":
        return "PARTIAL"
    findings = source.get("findings")
    if not isinstance(findings, list):
        return "UNKNOWN"
    if findings:
        return "PARTIAL"
    for row in coverage.values():
        if not isinstance(row, dict):
            return "UNKNOWN"
        if row.get("partial", 0) or row.get("unknown", 0):
            return "PARTIAL"
    pous = source.get("pous")
    if not isinstance(pous, list):
        return "UNKNOWN"
    for pou in pous:
        if not isinstance(pou, dict) or not isinstance(pou.get("records"), list):
            return "UNKNOWN"
        if not isinstance(pou.get("findings"), list):
            return "UNKNOWN"
        if pou["findings"]:
            return "PARTIAL"
        if any(not isinstance(record, dict) or record.get("status") != "decoded"
               for record in pou["records"]):
            return "PARTIAL"
    return "COMPLETE"


def _p004_source_state(source: dict[str, Any]) -> str:
    analysis = source.get("analysis")
    return analysis.get("state", "UNKNOWN") if isinstance(analysis, dict) else "UNKNOWN"


def source_state(source: dict[str, Any]) -> str:
    if source.get("schema_name") == reference.NEUTRAL_FORMAT:
        return _neutral_source_state(source)
    if source.get("schema_name") == reference.P004_FORMAT:
        return _p004_source_state(source)
    return "UNKNOWN"


def source_profile(source: dict[str, Any]) -> str | None:
    if source.get("schema_name") == reference.NEUTRAL_FORMAT:
        profile = source.get("profile")
        return profile.get("profile_id") if isinstance(profile, dict) else None
    return source.get("profile_id") if isinstance(source.get("profile_id"), str) else None


def comparison_profile(source: dict[str, Any]) -> tuple[Any, ...]:
    if source.get("schema_name") == reference.NEUTRAL_FORMAT:
        profile = source.get("profile")
        if not isinstance(profile, dict):
            return (None,)
        return tuple(profile.get(field) for field in
                     ("profile_id", "contract_version", "family", "cpu_ui_selection", "language",
                      "detector_status"))
    return (source_profile(source),)


def _validate_neutral_root(source: dict[str, Any]) -> None:
    _fail(source.get("schema_version") == "1.0.0", "NEUTRAL_IR_SCHEMA")
    _fail(set(source) == NEUTRAL_ROOT_FIELDS, "NEUTRAL_IR_SCHEMA")
    _fail(all(isinstance(source.get(field), dict) for field in
              ("producer", "input", "profile", "project", "coverage")), "NEUTRAL_IR_SCHEMA")
    _fail(all(isinstance(source.get(field), list) for field in
              ("pous", "comments", "labels", "findings")), "NEUTRAL_IR_SCHEMA")
    _fail(all(isinstance(source["profile"].get(field), str) for field in
              ("profile_id", "contract_version", "family", "cpu_ui_selection", "language",
               "detector_status")) and isinstance(source["profile"].get("evidence"), list),
          "NEUTRAL_IR_SCHEMA")
    _fail(set(source["coverage"]) == {"project", "pou", "record", "comment", "label"},
          "NEUTRAL_IR_SCHEMA")
    for row in source["coverage"].values():
        _fail(isinstance(row, dict) and set(row) == {"total", "decoded", "partial", "unknown"} and
              all(type(row[field]) is int and row[field] >= 0
                  for field in ("total", "decoded", "partial", "unknown")), "NEUTRAL_IR_SCHEMA")
    for finding in source["findings"]:
        _validate_finding(finding)
    for pou in source["pous"]:
        _fail(isinstance(pou, dict) and set(pou) == POU_FIELDS and
              isinstance(pou.get("pou_id"), str) and isinstance(pou.get("name"), str) and
              type(pou.get("execution_order")) is int and isinstance(pou.get("relations"), list) and
              isinstance(pou.get("records"), list) and isinstance(pou.get("findings"), list),
              "NEUTRAL_IR_SCHEMA")
        for finding in pou["findings"]:
            _validate_finding(finding)
        for record in pou["records"]:
            _fail(isinstance(record, dict) and set(record) == RECORD_FIELDS and
                  isinstance(record.get("record_id"), str) and type(record.get("sequence")) is int and
                  record.get("status") in {"decoded", "partial", "unknown"} and
                  isinstance(record.get("operands"), list), "NEUTRAL_IR_SCHEMA")
            _validate_provenance(record.get("provenance"))
            for operand in record["operands"]:
                _fail(isinstance(operand, dict) and set(operand) == OPERAND_FIELDS and
                      type(operand.get("position")) is int and isinstance(operand.get("raw_token"), str),
                      "NEUTRAL_IR_SCHEMA")
                _validate_provenance(operand.get("provenance"))
    for collection, fields in (("comments", {"scope", "program_id", "device_id", "language_slot",
                                               "value_state", "value", "provenance"}),
                               ("labels", {"scope", "program_id", "label_id", "language_slot",
                                             "value_state", "value", "provenance"})):
        for row in source[collection]:
            _fail(isinstance(row, dict) and set(row) == fields, "NEUTRAL_IR_SCHEMA")
            _validate_provenance(row.get("provenance"))


def _validate_provenance(value: Any) -> None:
    _fail(isinstance(value, dict) and set(value) == PROVENANCE_FIELDS and
          all(isinstance(value.get(field), str) for field in
              ("source_entry", "source_store", "source_locator", "source_digest")) and
          isinstance(value.get("relation_evidence"), list) and
          all(isinstance(item, str) for item in value["relation_evidence"]), "NEUTRAL_IR_SCHEMA")


def _validate_finding(value: Any) -> None:
    _fail(isinstance(value, dict) and set(value) == FINDING_FIELDS and
          all(isinstance(value.get(field), str) for field in FINDING_FIELDS), "NEUTRAL_IR_SCHEMA")


def _validate_p004_root(source: dict[str, Any]) -> None:
    _fail(type(source.get("schema_version")) is int and source.get("schema_version") == 1,
          "P004_REFERENCE_SCHEMA")
    _fail(isinstance(source.get("input"), dict) and isinstance(source.get("analysis"), dict) and
          source["analysis"].get("state") in {"COMPLETE", "PARTIAL"} and
          isinstance(source.get("coverage"), dict) and isinstance(source.get("occurrences"), list),
          "P004_REFERENCE_SCHEMA")


def _neutral_objects(source: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _validate_neutral_root(source)
    objects: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    pou_ids = []
    for pou_index, pou in enumerate(source["pous"]):
        _fail(isinstance(pou, dict) and isinstance(pou.get("pou_id"), str) and
              isinstance(pou.get("records"), list), "NEUTRAL_IR_SCHEMA")
        pou_id = pou["pou_id"]
        pou_ids.append(pou_id)
        objects.append({"kind": "pou", "identity": pou_id, "order": pou.get("execution_order"),
                        "status": "decoded", "provenance": None,
                        "content": {key: pou.get(key) for key in ("name", "language", "program_kind", "relations")}})
        record_ids = []
        for record_index, record in enumerate(pou["records"]):
            _fail(isinstance(record, dict) and isinstance(record.get("record_id"), str) and
                  isinstance(record.get("operands"), list), "NEUTRAL_IR_SCHEMA")
            record_id = record["record_id"]
            record_ids.append(record_id)
            parent = _key("pou", pou_id)
            objects.append({"kind": "record", "identity": _key(pou_id, record_id), "parent": parent,
                            "order": record.get("sequence"), "status": record.get("status"),
                            "provenance": record.get("provenance"),
                            "content": {key: record.get(key) for key in
                                        ("kind", "step", "opcode", "text", "continues_record_id")}})
            for operand_index, operand in enumerate(record["operands"]):
                _fail(isinstance(operand, dict), "NEUTRAL_IR_SCHEMA")
                objects.append({"kind": "operand", "identity": _key(pou_id, record_id, operand.get("position")),
                                "parent": _key(pou_id, record_id), "order": operand.get("position"),
                                "status": record.get("status"), "provenance": operand.get("provenance"),
                                "content": {key: operand.get(key) for key in
                                            ("raw_token", "kind", "value", "width", "indirection", "index")}})
        for duplicate in _duplicates(record_ids):
            conflicts.append({"kind": "DUPLICATE_RECORD_ID", "pou_id": pou_id, "identity": duplicate})
    for duplicate in _duplicates(pou_ids):
        conflicts.append({"kind": "DUPLICATE_POU_ID", "identity": duplicate})
    for kind, identity_fields in (("comment", ("scope", "program_id", "device_id", "language_slot")),
                                  ("label", ("scope", "program_id", "label_id", "language_slot"))):
        rows = source.get(kind + "s")
        _fail(isinstance(rows, list), "NEUTRAL_IR_SCHEMA")
        identities = []
        for order, row in enumerate(rows):
            _fail(isinstance(row, dict), "NEUTRAL_IR_SCHEMA")
            identity = _key(*(row.get(field) for field in identity_fields))
            identities.append(identity)
            objects.append({"kind": kind, "identity": identity, "order": order,
                            "status": row.get("value_state"), "provenance": row.get("provenance"),
                            "content": {key: row.get(key) for key in (*identity_fields, "value_state", "value")}})
        for duplicate in _duplicates(identities):
            conflicts.append({"kind": "DUPLICATE_" + kind.upper() + "_IDENTITY", "identity": duplicate})
    _fail(len(objects) <= MAX_OBJECTS, "EXPLORER_OBJECT_LIMIT")
    return objects, conflicts


def _p004_objects(source: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _validate_p004_root(source)
    objects: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    seen_pous: set[str] = set()
    occurrence_ids = []
    for occurrence in source["occurrences"]:
        _fail(isinstance(occurrence, dict) and isinstance(occurrence.get("occurrence_id"), str) and
              isinstance(occurrence.get("pou"), dict) and isinstance(occurrence.get("record"), dict) and
              isinstance(occurrence.get("operands"), list), "P004_REFERENCE_SCHEMA")
        provenance = occurrence.get("provenance")
        _fail(isinstance(provenance, dict), "P004_REFERENCE_SCHEMA")
        pou = occurrence["pou"]
        pou_identity = _key(provenance.get("source_store"), pou.get("name"))
        if pou_identity not in seen_pous:
            seen_pous.add(pou_identity)
            objects.append({"kind": "pou", "identity": pou_identity, "order": pou.get("order"),
                            "status": source_state(source), "provenance": provenance,
                            "content": {"name": pou.get("name"), "order_basis": pou.get("order_basis")}})
        occurrence_id = occurrence["occurrence_id"]
        occurrence_ids.append(occurrence_id)
        record = occurrence["record"]
        objects.append({"kind": "record", "identity": occurrence_id, "parent": pou_identity,
                        "order": record.get("sequence"), "status": source_state(source),
                        "provenance": provenance, "content": {"opcode": record.get("opcode")}})
        for operand in occurrence["operands"]:
            _fail(isinstance(operand, dict), "P004_REFERENCE_SCHEMA")
            objects.append({"kind": "operand", "identity": _key(occurrence_id, operand.get("position")),
                            "parent": occurrence_id, "order": operand.get("position"),
                            "status": operand.get("status"), "provenance": provenance,
                            "content": {key: operand.get(key) for key in
                                        ("raw_token", "kind", "device", "constant", "access",
                                         "access_basis", "coverage")}})
        comment = occurrence.get("comment")
        if comment is not None:
            _fail(isinstance(comment, dict), "P004_REFERENCE_SCHEMA")
            objects.append({"kind": "comment",
                            "identity": _key(occurrence_id, comment.get("scope"),
                                             comment.get("language_slot")),
                            "parent": occurrence_id, "order": record.get("sequence"),
                            "status": comment.get("state"), "provenance": provenance,
                            "content": {key: comment.get(key) for key in
                                        ("scope", "language_slot", "state", "value")}})
    for duplicate in _duplicates(occurrence_ids):
        conflicts.append({"kind": "DUPLICATE_OCCURRENCE_ID", "identity": duplicate})
    _fail(len(objects) <= MAX_OBJECTS, "EXPLORER_OBJECT_LIMIT")
    return objects, conflicts


def explore(source: dict[str, Any], *, source_pin: str | None = None, limit: int = 10_000) -> dict[str, Any]:
    _fail(type(limit) is int and 0 < limit <= MAX_OBJECTS, "EXPLORER_LIMIT")
    _fail(isinstance(source, dict) and source.get("schema_name") in
          {reference.P004_FORMAT, reference.NEUTRAL_FORMAT}, "EXPLORER_SOURCE_UNSUPPORTED")
    _reject_surrogates(source)
    if source["schema_name"] == reference.NEUTRAL_FORMAT:
        objects, conflicts = _neutral_objects(source)
    else:
        objects, conflicts = _p004_objects(source)
    counts = Counter(item["kind"] for item in objects)
    returned = objects[:limit]
    state = "CONFLICT" if conflicts else ("LIMIT_REACHED" if len(objects) > limit else source_state(source))
    return {"format": REPORT_FORMAT, "version": 1, "mode": "EXPLORE", "state": state,
            "source": {"schema_name": source["schema_name"], "schema_version": source.get("schema_version"),
                       "profile_id": source_profile(source), "sha256": source_pin,
                       "source_state": source_state(source)},
            "counts": dict(sorted(counts.items())), "object_count": len(objects),
            "returned_count": len(returned), "conflicts": conflicts, "objects": returned,
            "official_validation": "NOT_RUN", "production_adoption": "NOT_GRANTED"}


class Events:
    def __init__(self, limit: int):
        self.limit = limit
        self.total = 0
        self.items: list[dict[str, Any]] = []
        self.counts: Counter[str] = Counter()

    def add(self, kind: str, **details: Any) -> None:
        self.total += 1
        self.counts[kind] += 1
        if len(self.items) < self.limit:
            self.items.append({"kind": kind, **details})


def _relation_ids(record: dict[str, Any]) -> set[str]:
    provenance = record.get("provenance")
    evidence = provenance.get("relation_evidence", []) if isinstance(provenance, dict) else []
    return {item.removeprefix("record:") for item in evidence if isinstance(item, str)}


def _index_unique(rows: list[dict[str, Any]], field: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    _fail(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), "EXPLORER_DIFF_SCHEMA")
    values = [row.get(field) for row in rows]
    _fail(all(isinstance(value, str) for value in values), "EXPLORER_DIFF_SCHEMA")
    duplicates = _duplicates(values)
    return ({row[field]: row for row in rows if row[field] not in duplicates}, duplicates)


def _neutral_record_content(row: dict[str, Any]) -> dict[str, Any]:
    operands = row.get("operands")
    clean_operands = ([{key: value for key, value in operand.items() if key != "provenance"}
                       for operand in operands] if isinstance(operands, list) else operands)
    return {"kind": row.get("kind"), "step": row.get("step"), "opcode": row.get("opcode"),
            "operands": clean_operands, "text": row.get("text"), "status": row.get("status"),
            "continues_record_id": row.get("continues_record_id")}


def _neutral_diff(left: dict[str, Any], right: dict[str, Any], events: Events) -> bool:
    _validate_neutral_root(left)
    _validate_neutral_root(right)
    for field, event_kind in (("input", "INPUT_METADATA_CHANGED"), ("project", "PROJECT_CHANGED"),
                              ("profile", "PROFILE_METADATA_CHANGED"),
                              ("producer", "PRODUCER_CHANGED"), ("findings", "FINDINGS_CHANGED"),
                              ("coverage", "COVERAGE_CHANGED")):
        if left.get(field) != right.get(field):
            events.add(event_kind, before=left.get(field), after=right.get(field))
    left_pous, dup_left = _index_unique(left["pous"], "pou_id")
    right_pous, dup_right = _index_unique(right["pous"], "pou_id")
    conflict = False
    for side, duplicates in (("left", dup_left), ("right", dup_right)):
        for identity in duplicates:
            events.add("DUPLICATE_POU_ID", side=side, identity=identity); conflict = True
    for pou_id in sorted(set(left_pous) | set(right_pous)):
        before, after = left_pous.get(pou_id), right_pous.get(pou_id)
        if before is None:
            events.add("POU_ADDED", identity=pou_id, after=after); continue
        if after is None:
            events.add("POU_REMOVED", identity=pou_id, before=before); continue
        _fail(isinstance(before.get("records"), list) and isinstance(after.get("records"), list),
              "NEUTRAL_IR_SCHEMA")
        if before.get("execution_order") != after.get("execution_order"):
            events.add("POU_MOVED", identity=pou_id, before_order=before.get("execution_order"),
                       after_order=after.get("execution_order"))
        fields = ("name", "language", "program_kind", "relations", "findings")
        before_meta = {field: before.get(field) for field in fields}
        after_meta = {field: after.get(field) for field in fields}
        if before_meta != after_meta:
            events.add("POU_CHANGED", identity=pou_id, before=before_meta, after=after_meta)
        left_records, left_dups = _index_unique(before.get("records", []), "record_id")
        right_records, right_dups = _index_unique(after.get("records", []), "record_id")
        for side, duplicates in (("left", left_dups), ("right", right_dups)):
            for identity in duplicates:
                events.add("DUPLICATE_RECORD_ID", side=side, pou_id=pou_id, identity=identity); conflict = True
        pairs: list[tuple[str, str, str]] = [(record_id, record_id, "IDENTITY")
                                             for record_id in sorted(set(left_records) & set(right_records))]
        left_unmatched = set(left_records) - {pair[0] for pair in pairs}
        right_unmatched = set(right_records) - {pair[1] for pair in pairs}
        relation_candidates = {right_id: sorted(left_id for left_id in left_unmatched
                                                if left_id in _relation_ids(right_records[right_id]))
                               for right_id in right_unmatched}
        claimed_by: defaultdict[str, list[str]] = defaultdict(list)
        for right_id, candidates in relation_candidates.items():
            for left_id in candidates:
                claimed_by[left_id].append(right_id)
        ambiguous_right = {right_id for right_id, candidates in relation_candidates.items()
                           if len(candidates) > 1}
        ambiguous_left = {left_id for left_id, right_ids in claimed_by.items() if len(right_ids) > 1}
        for right_id in sorted(ambiguous_right):
            events.add("MATCH_CONFLICT", pou_id=pou_id, after_id=right_id,
                       candidates=relation_candidates[right_id])
            conflict = True
        for left_id in sorted(ambiguous_left):
            events.add("MATCH_CONFLICT", pou_id=pou_id, before_id=left_id,
                       candidates=sorted(claimed_by[left_id]))
            conflict = True
        for right_id in sorted(right_unmatched):
            candidates = relation_candidates[right_id]
            if len(candidates) == 1 and candidates[0] not in ambiguous_left:
                left_id = candidates[0]
                pairs.append((left_id, right_id, "RELATION_EVIDENCE"))
                left_unmatched.remove(left_id)
                events.add("RECORD_ID_CHANGED", pou_id=pou_id, before_id=left_id, after_id=right_id,
                           basis="RELATION_EVIDENCE")
        right_unmatched -= {pair[1] for pair in pairs}
        for left_id, right_id, basis in pairs:
            old, new = left_records[left_id], right_records[right_id]
            identity = {"pou_id": pou_id, "before_record_id": left_id, "after_record_id": right_id,
                        "basis": basis}
            if old.get("sequence") != new.get("sequence"):
                events.add("RECORD_MOVED", **identity, before_order=old.get("sequence"), after_order=new.get("sequence"))
            old_content = _neutral_record_content(old)
            new_content = _neutral_record_content(new)
            if old_content != new_content:
                events.add("RECORD_CHANGED", **identity, before=old_content, after=new_content)
            if old.get("provenance") != new.get("provenance"):
                events.add("PROVENANCE_CHANGED", object_kind="record", **identity,
                           before=old.get("provenance"), after=new.get("provenance"))
            old_operand_provenance = [{"position": item.get("position"), "provenance": item.get("provenance")}
                                      for item in old.get("operands", [])]
            new_operand_provenance = [{"position": item.get("position"), "provenance": item.get("provenance")}
                                      for item in new.get("operands", [])]
            if old_operand_provenance != new_operand_provenance:
                events.add("PROVENANCE_CHANGED", object_kind="operand", **identity,
                           before=old_operand_provenance, after=new_operand_provenance)
            if old.get("status") != "decoded" or new.get("status") != "decoded":
                events.add("COMPARISON_UNCERTAIN", object_kind="record", **identity,
                           before_status=old.get("status"), after_status=new.get("status"))
        for record_id in sorted(left_unmatched):
            events.add("RECORD_REMOVED", pou_id=pou_id, identity=record_id, before=left_records[record_id])
        for record_id in sorted(right_unmatched):
            events.add("RECORD_ADDED", pou_id=pou_id, identity=record_id, after=right_records[record_id])
    for collection, fields in (("comments", ("scope", "program_id", "device_id", "language_slot")),
                               ("labels", ("scope", "program_id", "label_id", "language_slot"))):
        left_rows, right_rows = left.get(collection), right.get(collection)
        _fail(isinstance(left_rows, list) and isinstance(right_rows, list), "NEUTRAL_IR_SCHEMA")
        _fail(all(isinstance(row, dict) for row in left_rows + right_rows), "NEUTRAL_IR_SCHEMA")
        left_group: defaultdict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        right_group: defaultdict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        for order, row in enumerate(left_rows): left_group[_key(*(row.get(field) for field in fields))].append((order, row))
        for order, row in enumerate(right_rows): right_group[_key(*(row.get(field) for field in fields))].append((order, row))
        for identity in sorted(set(left_group) | set(right_group)):
            before_rows, after_rows = left_group.get(identity, []), right_group.get(identity, [])
            if len(before_rows) > 1 or len(after_rows) > 1:
                events.add("DUPLICATE_" + collection[:-1].upper() + "_IDENTITY", identity=identity,
                           left_count=len(before_rows), right_count=len(after_rows)); conflict = True
                continue
            if not before_rows:
                events.add(collection[:-1].upper() + "_ADDED", identity=identity, after=after_rows[0][1]); continue
            if not after_rows:
                events.add(collection[:-1].upper() + "_REMOVED", identity=identity, before=before_rows[0][1]); continue
            before_order, old = before_rows[0]; after_order, new = after_rows[0]
            if before_order != after_order:
                events.add(collection[:-1].upper() + "_MOVED", identity=identity,
                           before_order=before_order, after_order=after_order)
            if old != new:
                events.add(collection[:-1].upper() + "_CHANGED", identity=identity, before=old, after=new)
    return conflict


def _p004_record_body(occurrence: dict[str, Any]) -> dict[str, Any]:
    return {"opcode": occurrence.get("record", {}).get("opcode"), "operands": occurrence.get("operands")}


def _p004_duplicate_signature(occurrence: dict[str, Any]) -> str:
    value = {key: occurrence.get(key) for key in ("record", "provenance", "comment", "operands")}
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _p004_pair_events(events: Events, pou_id: str, old: dict[str, Any], new: dict[str, Any],
                      basis: str) -> None:
    identity = {"pou_id": pou_id, "before_id": old["occurrence_id"],
                "after_id": new["occurrence_id"], "basis": basis}
    if old["record"].get("sequence") != new["record"].get("sequence"):
        events.add("RECORD_MOVED", **identity, before_order=old["record"].get("sequence"),
                   after_order=new["record"].get("sequence"))
    if old.get("provenance") != new.get("provenance"):
        events.add("PROVENANCE_CHANGED", object_kind="record", **identity,
                   before=old.get("provenance"), after=new.get("provenance"))
    if old.get("comment") != new.get("comment"):
        events.add("COMMENT_CHANGED", **identity, before=old.get("comment"), after=new.get("comment"))


def _p004_diff(left: dict[str, Any], right: dict[str, Any], events: Events) -> bool:
    _validate_p004_root(left)
    _validate_p004_root(right)
    conflict = False
    for field, event_kind in (("input", "INPUT_METADATA_CHANGED"), ("analysis", "ANALYSIS_CHANGED"),
                              ("coverage", "COVERAGE_CHANGED")):
        if left.get(field) != right.get(field):
            events.add(event_kind, before=left.get(field), after=right.get(field))
    def groups(source: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        result: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for occurrence in source["occurrences"]:
            _fail(isinstance(occurrence, dict) and isinstance(occurrence.get("pou"), dict) and
                  isinstance(occurrence.get("provenance"), dict) and
                  isinstance(occurrence.get("occurrence_id"), str) and
                  isinstance(occurrence.get("record"), dict) and
                  isinstance(occurrence.get("operands"), list), "P004_REFERENCE_SCHEMA")
            identity = _key(occurrence["provenance"].get("source_store"), occurrence["pou"].get("name"))
            result[identity].append(occurrence)
        return dict(result)
    left_groups, right_groups = groups(left), groups(right)
    for side, source in (("left", left), ("right", right)):
        for identity in _duplicates(row["occurrence_id"] for row in source["occurrences"]):
            events.add("DUPLICATE_OCCURRENCE_ID", side=side, identity=identity)
            conflict = True
    for pou_id in sorted(set(left_groups) | set(right_groups)):
        before, after = left_groups.get(pou_id), right_groups.get(pou_id)
        if before is None:
            events.add("POU_ADDED", identity=pou_id, after_count=len(after or [])); continue
        if after is None:
            events.add("POU_REMOVED", identity=pou_id, before_count=len(before)); continue
        before_pou, after_pou = before[0]["pou"], after[0]["pou"]
        if before_pou.get("order") != after_pou.get("order"):
            events.add("POU_MOVED", identity=pou_id, before_order=before_pou.get("order"),
                       after_order=after_pou.get("order"))
        if before_pou.get("order_basis") != after_pou.get("order_basis"):
            events.add("POU_CHANGED", identity=pou_id,
                       before={"order_basis": before_pou.get("order_basis")},
                       after={"order_basis": after_pou.get("order_basis")})
        left_bodies: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        right_bodies: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in before: left_bodies[json.dumps(_p004_record_body(row), ensure_ascii=False, sort_keys=True)].append(row)
        for row in after: right_bodies[json.dumps(_p004_record_body(row), ensure_ascii=False, sort_keys=True)].append(row)
        matched_left: set[str] = set(); matched_right: set[str] = set()
        for body in sorted(set(left_bodies) & set(right_bodies)):
            old_rows, new_rows = left_bodies[body], right_bodies[body]
            if len(old_rows) == len(new_rows) == 1:
                old, new = old_rows[0], new_rows[0]
                matched_left.add(old["occurrence_id"]); matched_right.add(new["occurrence_id"])
                _p004_pair_events(events, pou_id, old, new, "EXACT_UNIQUE_BODY")
            elif ({row["occurrence_id"]: _p004_duplicate_signature(row) for row in old_rows} ==
                  {row["occurrence_id"]: _p004_duplicate_signature(row) for row in new_rows} and
                  len({row["occurrence_id"] for row in old_rows}) == len(old_rows) and
                  len({row["occurrence_id"] for row in new_rows}) == len(new_rows)):
                matched_left.update(row["occurrence_id"] for row in old_rows)
                matched_right.update(row["occurrence_id"] for row in new_rows)
            else:
                events.add("MATCH_CONFLICT", pou_id=pou_id, basis="DUPLICATE_BODY",
                           left_count=len(old_rows), right_count=len(new_rows)); conflict = True
        left_unmatched = [row for row in before if row["occurrence_id"] not in matched_left]
        right_unmatched = [row for row in after if row["occurrence_id"] not in matched_right]
        for side, rows in (("left", left_unmatched), ("right", right_unmatched)):
            duplicate_sequences = _duplicates(str(row["record"].get("sequence")) for row in rows)
            for sequence in duplicate_sequences:
                events.add("MATCH_CONFLICT", pou_id=pou_id, side=side,
                           basis="DUPLICATE_SEQUENCE", sequence=sequence)
                conflict = True
        left_by_sequence = {row["record"].get("sequence"): row for row in left_unmatched}
        right_by_sequence = {row["record"].get("sequence"): row for row in right_unmatched}
        for sequence in sorted(set(left_by_sequence) & set(right_by_sequence)):
            old, new = left_by_sequence[sequence], right_by_sequence[sequence]
            events.add("RECORD_CHANGED", pou_id=pou_id, basis="SAME_SEQUENCE", sequence=sequence,
                       before=_p004_record_body(old), after=_p004_record_body(new))
            _p004_pair_events(events, pou_id, old, new, "SAME_SEQUENCE")
            matched_left.add(old["occurrence_id"]); matched_right.add(new["occurrence_id"])
        for row in before:
            if row["occurrence_id"] not in matched_left:
                events.add("RECORD_REMOVED", pou_id=pou_id, identity=row["occurrence_id"], before=row)
        for row in after:
            if row["occurrence_id"] not in matched_right:
                events.add("RECORD_ADDED", pou_id=pou_id, identity=row["occurrence_id"], after=row)
    if source_state(left) != "COMPLETE" or source_state(right) != "COMPLETE":
        events.add("COMPARISON_UNCERTAIN", object_kind="source",
                   before_status=source_state(left), after_status=source_state(right))
    return conflict


def diff(left: dict[str, Any], right: dict[str, Any], *, left_pin: str | None = None,
         right_pin: str | None = None, limit: int = MAX_EVENTS) -> dict[str, Any]:
    _fail(type(limit) is int and 0 < limit <= MAX_EVENTS, "EXPLORER_DIFF_LIMIT")
    _fail(isinstance(left, dict) and isinstance(right, dict), "EXPLORER_DIFF_SCHEMA")
    _reject_surrogates(left)
    _reject_surrogates(right)
    left_schema, right_schema = left.get("schema_name"), right.get("schema_name")
    base = {"format": REPORT_FORMAT, "version": 1, "mode": "DIFF",
            "left": {"schema_name": left_schema, "schema_version": left.get("schema_version"),
                     "profile_id": source_profile(left), "sha256": left_pin, "source_state": source_state(left)},
            "right": {"schema_name": right_schema, "schema_version": right.get("schema_version"),
                      "profile_id": source_profile(right), "sha256": right_pin, "source_state": source_state(right)},
            "official_validation": "NOT_RUN", "production_adoption": "NOT_GRANTED"}
    if left_schema != right_schema or left_schema not in {reference.P004_FORMAT, reference.NEUTRAL_FORMAT}:
        return {**base, "decision": "NOT_COMPARABLE", "reason": "SOURCE_SCHEMA_MISMATCH",
                "event_count": 0, "returned_count": 0, "event_counts": {}, "events": []}
    if left.get("schema_version") != right.get("schema_version"):
        return {**base, "decision": "NOT_COMPARABLE", "reason": "SOURCE_VERSION_MISMATCH",
                "event_count": 0, "returned_count": 0, "event_counts": {}, "events": []}
    if left_schema == reference.NEUTRAL_FORMAT:
        _validate_neutral_root(left)
        _validate_neutral_root(right)
    else:
        _validate_p004_root(left)
        _validate_p004_root(right)
    if comparison_profile(left) != comparison_profile(right):
        return {**base, "decision": "NOT_COMPARABLE", "reason": "PROFILE_MISMATCH",
                "event_count": 0, "returned_count": 0, "event_counts": {}, "events": []}
    events = Events(limit)
    conflict = (_neutral_diff(left, right, events) if left_schema == reference.NEUTRAL_FORMAT
                else _p004_diff(left, right, events))
    uncertain = bool(events.counts.get("COMPARISON_UNCERTAIN")) or source_state(left) != "COMPLETE" or source_state(right) != "COMPLETE"
    substantive = events.total - events.counts.get("COMPARISON_UNCERTAIN", 0)
    if conflict:
        decision, reason = "BLOCKED", "IDENTITY_OR_MATCH_CONFLICT"
    elif uncertain and substantive:
        decision, reason = "PARTIAL_DIFFERENCE", "SOURCE_OR_OBJECT_PARTIAL"
    elif uncertain:
        decision, reason = "NOT_COMPARABLE", "SOURCE_OR_OBJECT_PARTIAL"
    elif substantive:
        decision, reason = "DIFFERENT", None
    else:
        decision, reason = "SAME", None
    if events.total > limit:
        reason = "EVENT_LIMIT" if reason is None else reason + "+EVENT_LIMIT"
    return {**base, "decision": decision, "reason": reason, "event_count": events.total,
            "returned_count": len(events.items), "event_counts": dict(sorted(events.counts.items())),
            "events": events.items}


def render_text(report: dict[str, Any]) -> str:
    if report["mode"] == "EXPLORE":
        lines = [f"mode=EXPLORE state={report['state']} objects={report['object_count']} returned={report['returned_count']}",
                 "counts=" + json.dumps(report["counts"], ensure_ascii=False, sort_keys=True)]
        for item in report["objects"]:
            lines.append(f"{item['kind']}\t{item['identity']}\torder={item.get('order')}\tstatus={item.get('status')}")
    else:
        lines = [f"mode=DIFF decision={report['decision']} events={report['event_count']} returned={report['returned_count']}",
                 "counts=" + json.dumps(report["event_counts"], ensure_ascii=False, sort_keys=True)]
        for item in report["events"]:
            identity = item.get("identity") or item.get("pou_id") or item.get("before_record_id") or "-"
            lines.append(f"{item['kind']}\t{identity}")
    lines.append("official_validation=NOT_RUN production_adoption=NOT_GRANTED")
    return "\n".join(lines) + "\n"


def _publish(path: Path, payload: bytes) -> None:
    safe._publish_new(path, payload)


def _publish_outputs(json_path: Path, json_payload: bytes, text_path: Path | None,
                     text_payload: bytes) -> None:
    if text_path is None:
        _publish(json_path, json_payload)
        return
    _publish(text_path, text_payload)
    try:
        _publish(json_path, json_payload)
    except (safe.LedgerError, OSError) as error:
        raise ExplorerDiffError("OUTPUT_SET_INCOMPLETE_TEXT_ONLY") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("explore", "diff"))
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--left-sha256", required=True)
    parser.add_argument("--right", type=Path)
    parser.add_argument("--right-sha256")
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--text-output", type=Path)
    parser.add_argument("--limit", type=int, default=MAX_EVENTS)
    args = parser.parse_args(argv)
    try:
        left_body, left_pin = reference._read_pinned_input(args.left, args.left_sha256)
        left = safe._json_no_duplicates(left_body)
        if args.mode == "explore":
            _fail(args.right is None and args.right_sha256 is None, "EXPLORER_RIGHT_FORBIDDEN")
            report = explore(left, source_pin=left_pin, limit=args.limit)
        else:
            _fail(args.right is not None and args.right_sha256 is not None, "DIFF_RIGHT_REQUIRED")
            right_body, right_pin = reference._read_pinned_input(args.right, args.right_sha256)
            right = safe._json_no_duplicates(right_body)
            report = diff(left, right, left_pin=left_pin, right_pin=right_pin, limit=args.limit)
            right_again, right_again_pin = reference._read_pinned_input(args.right, args.right_sha256)
            _fail(right_again == right_body and right_again_pin == right_pin, "INPUT_CHANGED_DURING_DIFF")
        left_again, left_again_pin = reference._read_pinned_input(args.left, args.left_sha256)
        _fail(left_again == left_body and left_again_pin == left_pin, "INPUT_CHANGED_DURING_DIFF")
        json_payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        text_payload = render_text(report).encode("utf-8")
        _fail(args.text_output is None or
              args.json_output.resolve(strict=False) != args.text_output.resolve(strict=False),
              "OUTPUT_PATH_COLLISION")
        _fail(not args.json_output.exists() and (args.text_output is None or not args.text_output.exists()),
              "OUTPUT_EXISTS")
        _publish_outputs(args.json_output, json_payload, args.text_output, text_payload)
    except (safe.LedgerError, OSError) as error:
        code = error.code if isinstance(error, safe.LedgerError) else "EXPLORER_DIFF_IO"
        print(json.dumps({"decision": "BLOCKED", "reason": code, "official_validation": "NOT_RUN"}, sort_keys=True))
        return 1
    decision = report.get("decision", report.get("state"))
    count = report.get("event_count", report.get("object_count"))
    print(json.dumps({"decision": decision, "count": count, "official_validation": "NOT_RUN"}, sort_keys=True))
    return 1 if decision == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
