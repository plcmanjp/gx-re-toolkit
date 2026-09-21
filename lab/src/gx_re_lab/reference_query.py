"""Query GXW reference projections and FX5/R-series Neutral IR without upgrading authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from . import coverage_ledger as safe

REPORT_FORMAT = "plcman.gx-re-lab.reference-query"
P004_FORMAT = "plcman.gxw.reference-ir"
NEUTRAL_FORMAT = "plcman.gx3.neutral-ir"
MAX_RESULTS = 10_000
MAX_INPUT_BYTES = 64 * 1024 * 1024


class ReferenceQueryError(safe.LedgerError):
    pass


def _fail(condition: bool, code: str = "REFERENCE_QUERY_SCHEMA") -> None:
    if not condition:
        raise ReferenceQueryError(code)


def _text(value: object, *, empty: bool = False, limit: int = 1024) -> str:
    _fail(isinstance(value, str) and len(value) <= limit and (empty or bool(value)) and
          not any(0xD800 <= ord(char) <= 0xDFFF for char in value))
    return value


def validate_selector(value: object) -> dict[str, Any]:
    _fail(isinstance(value, dict) and isinstance(value.get("mode"), str))
    mode = value["mode"]
    if mode == "RAW_TOKEN":
        _fail(set(value) == {"mode", "raw_token"})
        return {"mode": mode, "raw_token": _text(value["raw_token"], empty=True)}
    if mode == "PHYSICAL":
        _fail(set(value) == {"mode", "family", "address", "module", "word_bit", "include_covered"})
        _fail(type(value["address"]) is int and value["address"] >= 0)
        _fail(value["module"] is None or (type(value["module"]) is int and value["module"] >= 0))
        _fail(value["word_bit"] is None or (type(value["word_bit"]) is int and value["word_bit"] >= 0))
        _fail(type(value["include_covered"]) is bool)
        return {**value, "family": _text(value["family"], limit=16)}
    if mode == "COMMENT":
        _fail(set(value) == {"mode", "device_id", "scope", "language_slot"})
        _fail(value["scope"] is None or isinstance(value["scope"], str))
        _fail(value["language_slot"] is None or isinstance(value["language_slot"], str))
        return {"mode": mode, "device_id": _text(value["device_id"], limit=256),
                "scope": None if value["scope"] is None else _text(value["scope"], limit=128),
                "language_slot": None if value["language_slot"] is None else _text(value["language_slot"], limit=128)}
    raise ReferenceQueryError("REFERENCE_QUERY_MODE")


def _read_pinned_input(path: Path, pin: str) -> tuple[bytes, str]:
    safe._fail(isinstance(pin, str) and len(pin) == 64 and set(pin.casefold()) <= safe.HEX,
               "REFERENCE_INPUT_PIN_SCHEMA")
    checked = safe._regular_no_link(path, "REFERENCE_INPUT")
    digest = hashlib.sha256()
    chunks, total = [], 0
    with checked.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            _fail(total <= MAX_INPUT_BYTES, "REFERENCE_INPUT_CAP")
            digest.update(block)
            chunks.append(block)
    actual = digest.hexdigest()
    _fail(actual == pin.casefold(), "REFERENCE_INPUT_PIN_MISMATCH")
    return b"".join(chunks), actual


def _base(source: dict[str, Any], selector: dict[str, Any], source_pin: str | None) -> dict[str, Any]:
    return {
        "format": REPORT_FORMAT,
        "version": 1,
        "source": {"schema_name": source.get("schema_name"), "schema_version": source.get("schema_version"),
                   "sha256": source_pin},
        "selector": selector,
        "official_validation": "NOT_RUN",
        "production_adoption": "NOT_GRANTED",
    }


def _finish(base: dict[str, Any], *, state: str, reason: str | None, source_state: str, evaluated: int,
            source_total: int | None, unknown: int | None, matches: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    limited = len(matches) > limit
    visible = matches[:limit]
    if limited:
        state, reason = "LIMIT_REACHED", "RESULT_LIMIT"
    return {**base, "state": state, "reason": reason, "source_state": source_state,
            "denominator": {"evaluated": evaluated, "source_total": source_total, "unknown": unknown},
            "match_count": len(matches), "returned_count": len(visible), "matches": visible}


def _physical_match(selector: dict[str, Any], identity: dict[str, Any]) -> bool:
    return all(identity.get(field) == selector[field] for field in ("family", "address", "module", "word_bit"))


def _query_p004(source: dict[str, Any], selector: dict[str, Any], base: dict[str, Any], limit: int) -> dict[str, Any]:
    _fail(type(source.get("schema_version")) is int and source.get("schema_version") == 1 and
          isinstance(source.get("occurrences"), list), "P004_REFERENCE_SCHEMA")
    _fail(isinstance(source.get("analysis"), dict) and
          source["analysis"].get("state") in {"COMPLETE", "PARTIAL"}, "P004_REFERENCE_SCHEMA")
    if selector["mode"] == "COMMENT":
        return _finish(base, state="EVALUATION_UNAVAILABLE", reason="P004_COMMENT_SCOPE_NOT_PRESERVED",
                       source_state=source.get("analysis", {}).get("state", "UNKNOWN"),
                       evaluated=0, source_total=None, unknown=None, matches=[], limit=limit)
    matches: list[dict[str, Any]] = []
    evaluated = 0
    unknown = 0
    for occurrence in source["occurrences"]:
        _fail(isinstance(occurrence, dict) and isinstance(occurrence.get("operands"), list), "P004_REFERENCE_SCHEMA")
        for operand in occurrence["operands"]:
            _fail(isinstance(operand, dict), "P004_REFERENCE_SCHEMA")
            evaluated += 1
            if operand.get("status") != "decoded":
                unknown += 1
            match_kind = None
            offset = None
            if selector["mode"] == "RAW_TOKEN":
                match_kind = "RAW_TOKEN" if operand.get("raw_token") == selector["raw_token"] else None
            elif operand.get("kind") == "device" and isinstance(operand.get("device"), dict):
                device = operand["device"]
                named = {field: device.get(field) for field in ("family", "address", "module", "word_bit")}
                if _physical_match(selector, named):
                    match_kind = "NAMED_ADDRESS"
                    offset = 0
                elif selector["include_covered"]:
                    coverage = operand.get("coverage", {})
                    addresses = coverage.get("addresses") if isinstance(coverage, dict) else None
                    if isinstance(addresses, list):
                        covered = next((item for item in addresses if isinstance(item, dict) and
                                        _physical_match(selector, item)), None)
                        if covered is not None:
                            match_kind = "COVERED_ADDRESS"
                            offset = covered.get("offset")
            if match_kind:
                matches.append({"match_kind": match_kind, "range_offset": offset,
                                "occurrence_id": occurrence.get("occurrence_id"), "pou": occurrence.get("pou"),
                                "record": occurrence.get("record"), "operand_position": operand.get("position"),
                                "raw_token": operand.get("raw_token"), "access": operand.get("access"),
                                "access_basis": operand.get("access_basis"),
                                "provenance": occurrence.get("provenance")})
    analysis = source.get("analysis", {})
    partial = unknown > 0 or (isinstance(analysis, dict) and analysis.get("state") != "COMPLETE")
    state = "PARTIAL" if partial else ("COMPLETE" if matches else "ZERO_RESULTS")
    reason = "SOURCE_PARTIAL" if partial else None
    return _finish(base, state=state, reason=reason, source_state="PARTIAL" if partial else "COMPLETE",
                   evaluated=evaluated, source_total=evaluated,
                   unknown=unknown, matches=matches, limit=limit)


def _neutral_operand_matches(source: dict[str, Any], token: str) -> tuple[list[dict[str, Any]], int, int]:
    matches, evaluated, unknown = [], 0, 0
    pous = source.get("pous")
    _fail(isinstance(pous, list), "NEUTRAL_IR_SCHEMA")
    for pou in pous:
        _fail(isinstance(pou, dict) and isinstance(pou.get("records"), list), "NEUTRAL_IR_SCHEMA")
        for record in pou["records"]:
            _fail(isinstance(record, dict) and isinstance(record.get("operands"), list), "NEUTRAL_IR_SCHEMA")
            if record.get("status") != "decoded":
                unknown += len(record["operands"]) or 1
            for operand in record["operands"]:
                _fail(isinstance(operand, dict), "NEUTRAL_IR_SCHEMA")
                evaluated += 1
                if operand.get("raw_token") == token:
                    matches.append({"match_kind": "RAW_TOKEN", "range_offset": None,
                                    "pou": {"pou_id": pou.get("pou_id"), "name": pou.get("name"),
                                            "order": pou.get("execution_order")},
                                    "record": {"record_id": record.get("record_id"),
                                               "sequence": record.get("sequence"), "opcode": record.get("opcode")},
                                    "operand_position": operand.get("position"), "raw_token": operand.get("raw_token"),
                                    "access": "unknown", "access_basis": "NEUTRAL_IR_DOES_NOT_ASSERT_ACCESS",
                                    "provenance": operand.get("provenance") or record.get("provenance")})
    return matches, evaluated, unknown


def _neutral_comment_matches(source: dict[str, Any], selector: dict[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
    comments = source.get("comments")
    _fail(isinstance(comments, list), "NEUTRAL_IR_SCHEMA")
    matches = []
    unknown = 0
    for comment in comments:
        _fail(isinstance(comment, dict), "NEUTRAL_IR_SCHEMA")
        if comment.get("value_state") in {"OBJECT_ABSENT", "SLOT_ABSENT", "EXPORT_ROW_OMITTED"}:
            unknown += 1
        if (comment.get("device_id") == selector["device_id"] and
                (selector["scope"] is None or comment.get("scope") == selector["scope"]) and
                (selector["language_slot"] is None or comment.get("language_slot") == selector["language_slot"])):
            matches.append({"scope": comment.get("scope"), "program_id": comment.get("program_id"),
                            "device_id": comment.get("device_id"), "language_slot": comment.get("language_slot"),
                            "value_state": comment.get("value_state"), "value": comment.get("value"),
                            "provenance": comment.get("provenance")})
    return matches, len(comments), unknown


def _query_neutral(source: dict[str, Any], selector: dict[str, Any], base: dict[str, Any], limit: int) -> dict[str, Any]:
    _fail(isinstance(source.get("schema_version"), str) and source.get("schema_version") == "1.0.0",
          "NEUTRAL_IR_VERSION")
    if selector["mode"] == "PHYSICAL":
        record_coverage = source.get("coverage", {}).get("record", {})
        source_partial = (not isinstance(record_coverage, dict) or
                          bool(record_coverage.get("partial", 0)) or bool(record_coverage.get("unknown", 0)))
        return _finish(base, state="EVALUATION_UNAVAILABLE", reason="NEUTRAL_IR_PHYSICAL_RANGE_NOT_ASSERTED",
                       source_state="PARTIAL" if source_partial else "COMPLETE",
                       evaluated=0, source_total=None, unknown=None, matches=[], limit=limit)
    if selector["mode"] == "RAW_TOKEN":
        matches, evaluated, unknown = _neutral_operand_matches(source, selector["raw_token"])
    else:
        matches, evaluated, unknown = _neutral_comment_matches(source, selector)
    coverage = source.get("coverage", {})
    coverage_key = "comment" if selector["mode"] == "COMMENT" else "record"
    row = coverage.get(coverage_key, {}) if isinstance(coverage, dict) else {}
    source_partial = not isinstance(row, dict) or row.get("partial", 0) or row.get("unknown", 0)
    state = "PARTIAL" if source_partial or unknown else ("COMPLETE" if matches else "ZERO_RESULTS")
    return _finish(base, state=state, reason="SOURCE_PARTIAL" if state == "PARTIAL" else None,
                   source_state="PARTIAL" if source_partial or unknown else "COMPLETE",
                   evaluated=evaluated, source_total=evaluated, unknown=unknown, matches=matches, limit=limit)


def query(source: dict[str, Any], selector: dict[str, Any], *, limit: int = 1000,
          source_pin: str | None = None) -> dict[str, Any]:
    _fail(type(limit) is int and 0 < limit <= MAX_RESULTS, "REFERENCE_QUERY_LIMIT")
    selector = validate_selector(selector)
    _fail(isinstance(source, dict) and isinstance(source.get("schema_name"), str))
    base = _base(source, selector, source_pin)
    if source["schema_name"] == P004_FORMAT:
        return _query_p004(source, selector, base, limit)
    if source["schema_name"] == NEUTRAL_FORMAT:
        return _query_neutral(source, selector, base, limit)
    raise ReferenceQueryError("REFERENCE_SOURCE_UNSUPPORTED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--selector", required=True, type=Path)
    parser.add_argument("--selector-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args(argv)
    try:
        source_body, source_pin = _read_pinned_input(args.input, args.input_sha256)
        selector_body, _selector_pin = safe._read_pinned(args.selector, args.selector_sha256)
        source = safe._json_no_duplicates(source_body)
        selector = safe._json_no_duplicates(selector_body)
        report = query(source, selector, limit=args.limit, source_pin=source_pin)
        source_again, source_again_pin = _read_pinned_input(args.input, args.input_sha256)
        selector_again, selector_again_pin = safe._read_pinned(args.selector, args.selector_sha256)
        _fail(source_again == source_body and selector_again == selector_body and
              source_again_pin == source_pin and selector_again_pin == _selector_pin,
              "INPUT_CHANGED_DURING_QUERY")
        payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        safe._publish_new(args.output, payload)
    except (safe.LedgerError, OSError) as error:
        code = error.code if isinstance(error, safe.LedgerError) else "REFERENCE_QUERY_IO"
        print(json.dumps({"state": "BLOCKED", "reason": code, "official_validation": "NOT_RUN"}, sort_keys=True))
        return 1
    print(json.dumps({"state": report["state"], "match_count": report["match_count"],
                      "returned_count": report["returned_count"], "official_validation": "NOT_RUN"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
