"""Compare two normalized research observations without running either tool.

The adapter accepts pinned, strict JSON produced by a caller-owned normalization
step. It preserves record order and duplicates, separates not-run from
not-comparable, and never turns agreement into official validation or product
adoption. No external repository code or runtime is imported.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import coverage_ledger as safe

FORMAT = "plcman.gx-re-lab.normalized-observation"
REPORT_FORMAT = "plcman.gx-re-lab.external-comparison"
MAX_RECORDS = 200_000
EXECUTION_STATES = {"COMPLETED", "NOT_RUN", "UNSUPPORTED", "FAILED", "PARTIAL"}
RECORD_KINDS = {"instruction", "statement", "note", "continuation", "opaque"}
RECORD_STATES = {"decoded", "partial", "unknown"}


class ExternalCompareError(safe.LedgerError):
    pass


def _fail(condition: bool, code: str = "OBSERVATION_SCHEMA") -> None:
    if not condition:
        raise ExternalCompareError(code)


def _text(value: object, *, empty: bool = False, limit: int = 512) -> str:
    _fail(isinstance(value, str) and len(value) <= limit and (empty or bool(value)) and
          not any(0xD800 <= ord(char) <= 0xDFFF for char in value))
    return value


def _source(value: object) -> dict[str, str]:
    _fail(isinstance(value, dict) and set(value) == {"sha256", "profile_id", "carrier"})
    return {
        "sha256": safe._sha256(value["sha256"]),
        "profile_id": _text(value["profile_id"], limit=128),
        "carrier": _text(value["carrier"], limit=128),
    }


def _execution(value: object) -> dict[str, str | None]:
    _fail(isinstance(value, dict) and set(value) == {"state", "reason"})
    state, reason = value["state"], value["reason"]
    _fail(isinstance(state, str) and state in EXECUTION_STATES)
    if state == "COMPLETED":
        _fail(reason is None)
    else:
        reason = _text(reason)
    return {"state": state, "reason": reason}


def _record(value: object) -> dict[str, Any]:
    keys = {"pou_id", "record_id", "sequence", "kind", "opcode", "operands", "locator", "digest", "status"}
    _fail(isinstance(value, dict) and set(value) == keys, "RECORD_SCHEMA")
    _fail(type(value["sequence"]) is int and value["sequence"] >= 0, "RECORD_SCHEMA")
    _fail(isinstance(value["kind"], str) and value["kind"] in RECORD_KINDS and
          isinstance(value["status"], str) and value["status"] in RECORD_STATES, "RECORD_SCHEMA")
    _fail(value["opcode"] is None or isinstance(value["opcode"], str), "RECORD_SCHEMA")
    _fail(isinstance(value["operands"], list) and len(value["operands"]) <= 64 and
          all(isinstance(item, str) and len(item) <= 1024 for item in value["operands"]), "RECORD_SCHEMA")
    return {
        "pou_id": _text(value["pou_id"], limit=256),
        "record_id": _text(value["record_id"], limit=256),
        "sequence": value["sequence"],
        "kind": value["kind"],
        "opcode": None if value["opcode"] is None else _text(value["opcode"], empty=True, limit=256),
        "operands": [_text(item, empty=True, limit=1024) for item in value["operands"]],
        "locator": _text(value["locator"], limit=1024),
        "digest": safe._sha256(value["digest"]),
        "status": value["status"],
    }


def read_observation(path: Path, pin: str) -> tuple[dict[str, Any], str]:
    body, digest = safe._read_pinned(path, pin)
    value = safe._json_no_duplicates(body)
    _fail(isinstance(value, dict) and
          set(value) == {"format", "version", "observation_id", "tool", "evidence_mode", "source", "execution", "records"})
    _fail(value["format"] == FORMAT and value["version"] == 1)
    safe._identifier(value["observation_id"])
    tool = value["tool"]
    _fail(isinstance(tool, dict) and set(tool) == {"id", "version", "source_commit"})
    normalized_tool = {
        "id": safe._identifier(tool["id"]),
        "version": _text(tool["version"], limit=128),
        "source_commit": safe._sha256(tool["source_commit"]),
    }
    _fail(isinstance(value["evidence_mode"], str) and
          value["evidence_mode"] in {"SYNTHETIC_FIXTURE", "OBSERVED_LOCAL"})
    records = value["records"]
    _fail(isinstance(records, list) and len(records) <= MAX_RECORDS, "RECORD_COUNT")
    normalized_records = [_record(record) for record in records]
    execution = _execution(value["execution"])
    _fail(execution["state"] == "COMPLETED" or not normalized_records, "NONCOMPLETED_RECORDS")
    return {
        "observation_id": value["observation_id"],
        "tool": normalized_tool,
        "evidence_mode": value["evidence_mode"],
        "source": _source(value["source"]),
        "execution": execution,
        "records": normalized_records,
    }, digest


def _coverage(records: list[dict[str, Any]]) -> dict[str, int]:
    result = {"total": len(records), "decoded": 0, "partial": 0, "unknown": 0}
    for record in records:
        result[record["status"]] += 1
    return result


def _base(left: dict[str, Any], right: dict[str, Any], pins: tuple[str, str]) -> dict[str, Any]:
    return {
        "format": REPORT_FORMAT,
        "version": 1,
        "official_validation": "NOT_RUN",
        "production_adoption": "NOT_GRANTED",
        "comparison_scope": "NORMALIZED_RECORDS_ONLY",
        "inputs": [
            {"side": "left", "observation_id": left["observation_id"], "sha256": pins[0],
             "tool": left["tool"], "evidence_mode": left["evidence_mode"], "execution": left["execution"]},
            {"side": "right", "observation_id": right["observation_id"], "sha256": pins[1],
             "tool": right["tool"], "evidence_mode": right["evidence_mode"], "execution": right["execution"]},
        ],
        "coverage": {"left": _coverage(left["records"]), "right": _coverage(right["records"])},
    }


def compare(left: dict[str, Any], right: dict[str, Any], pins: tuple[str, str]) -> dict[str, Any]:
    report = _base(left, right, pins)
    states = (left["execution"]["state"], right["execution"]["state"])
    if "NOT_RUN" in states:
        return {**report, "decision": "NOT_RUN", "reason": "TOOL_NOT_RUN", "comparison": None}
    if "UNSUPPORTED" in states:
        return {**report, "decision": "NOT_COMPARABLE", "reason": "TOOL_UNSUPPORTED", "comparison": None}
    if any(state in {"FAILED", "PARTIAL"} for state in states):
        return {**report, "decision": "BLOCKED", "reason": "EXECUTION_INCOMPLETE", "comparison": None}
    if left["source"] != right["source"]:
        return {**report, "decision": "NOT_COMPARABLE", "reason": "SOURCE_IDENTITY_MISMATCH", "comparison": None}

    left_records, right_records = left["records"], right["records"]
    denominator = max(len(left_records), len(right_records))
    compared = min(len(left_records), len(right_records))
    mismatch_count = abs(len(left_records) - len(right_records))
    first: dict[str, Any] | None = None
    for index in range(compared):
        if left_records[index] != right_records[index]:
            mismatch_count += 1
            if first is None:
                first = {"index": index, "left": left_records[index], "right": right_records[index]}
    if first is None and len(left_records) != len(right_records):
        index = compared
        first = {"index": index,
                 "left": left_records[index] if index < len(left_records) else None,
                 "right": right_records[index] if index < len(right_records) else None}
    comparison = {"denominator": denominator, "paired_records": compared,
                  "mismatch_count": mismatch_count, "first_difference": first}
    decision = "RESEARCH_MATCH" if mismatch_count == 0 else "RESEARCH_MISMATCH"
    return {**report, "decision": decision, "reason": None, "source": left["source"], "comparison": comparison}


def run(left_path: Path, left_pin: str, right_path: Path, right_pin: str) -> dict[str, Any]:
    left, actual_left = read_observation(left_path, left_pin)
    right, actual_right = read_observation(right_path, right_pin)
    report = compare(left, right, (actual_left, actual_right))
    left_again, left_again_pin = read_observation(left_path, left_pin)
    right_again, right_again_pin = read_observation(right_path, right_pin)
    _fail(left_again == left and right_again == right and
          (left_again_pin, right_again_pin) == (actual_left, actual_right), "INPUT_CHANGED_DURING_COMPARE")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--left-sha256", required=True)
    parser.add_argument("--right", required=True, type=Path)
    parser.add_argument("--right-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = run(args.left, args.left_sha256, args.right, args.right_sha256)
        payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        safe._publish_new(args.output, payload)
    except (safe.LedgerError, OSError) as error:
        code = error.code if isinstance(error, safe.LedgerError) else "EXTERNAL_COMPARE_IO"
        print(json.dumps({"decision": "BLOCKED", "official_validation": "NOT_RUN", "blocker": code}, sort_keys=True))
        return 1
    print(json.dumps({"decision": report["decision"], "official_validation": "NOT_RUN",
                      "mismatch_count": None if report["comparison"] is None else report["comparison"]["mismatch_count"]},
                     sort_keys=True))
    return 0 if report["decision"] in {"RESEARCH_MATCH", "RESEARCH_MISMATCH", "NOT_RUN", "NOT_COMPARABLE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
