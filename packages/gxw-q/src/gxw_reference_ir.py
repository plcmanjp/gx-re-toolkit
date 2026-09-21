#!/usr/bin/env python
"""Build a loss-preserving GXW reference projection from decoded POU rows.

This module is a read-only research projection.  It does not replace the
legacy gxw_pou_devmap TSV and does not claim GX display, compile, or runtime
validation.  Physical ranges are expanded only for closed, direct forms.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any

import gxw_ladder_reader as reader
import gxw_pou_devmap as legacy

SCHEMA_NAME = "plcman.gxw.reference-ir"
SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_OCCURRENCES = 1_000_000
MAX_OPERANDS = 5_000_000
MAX_TOTAL_COVERED_ADDRESSES = 1_000_000
MAX_COVERED_ADDRESSES = 4096
HEX_FAMILIES = {"X", "Y", "B", "W", "SB", "SW"}
BIT_FAMILIES = {"X", "Y", "M", "L", "F", "B", "SM", "SB", "T", "C"}
RMW_DEST = {"INC", "INCP", "DINC", "DINCP", "DEC", "DECP", "DDEC", "DDECP",
            "DNEG", "SFL", "SFR", "SFT", "SFTP", "BSFL", "BSFR"}
DOUBLE_WORD = {"DMOV", "DMOVP", "D+", "D-", "D*", "D/", "DAND", "DOR", "DXOR",
               "DINC", "DINCP", "DDEC", "DDECP", "DNEG"}
DEVICE = re.compile(
    r"^(?P<indirect>@)?(?:(?P<digit>K[1-8]))?(?:U(?P<module>[0-9]+)\\)?"
    r"(?P<family>ZR|SM|SD|FD|SB|SW|X|Y|M|L|F|B|D|R|W|T|C|Z|G)"
    r"(?P<address>[0-9A-F]+)(?P<index>ZZ?[0-9]+)?(?:\.(?P<bit>[0-9A-F]+))?$"
)
CONSTANT = re.compile(r"^(?P<kind>K|H|E)(?P<value>.+)$")


class ReferenceIrError(ValueError):
    pass


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _parse_int(text: str, radix: int) -> int | None:
    try:
        return int(text, radix)
    except ValueError:
        return None


def parse_operand(raw_token: str, position: int) -> dict[str, Any]:
    'Source-derived parser observation.'
    base: dict[str, Any] = {
        "position": position,
        "raw_token": raw_token,
        "kind": "unknown",
        "status": "unknown",
        "device": None,
        "constant": None,
    }
    if raw_token.startswith('"') and raw_token.endswith('"'):
        return {**base, "kind": "literal", "status": "decoded"}
    constant = CONSTANT.fullmatch(raw_token)
    if constant:
        radix = 16 if constant.group("kind") == "H" else 10
        value = _parse_int(constant.group("value"), radix)
        return {**base, "kind": "constant", "status": "decoded" if value is not None else "unknown",
                "constant": {"notation": constant.group("kind"), "value": value}}
    match = DEVICE.fullmatch(raw_token)
    if not match:
        return base
    family = match.group("family")
    radix = 16 if family in HEX_FAMILIES else 10
    address = _parse_int(match.group("address"), radix)
    bit = _parse_int(match.group("bit"), 16) if match.group("bit") is not None else None
    index_text = match.group("index")
    index = None
    if index_text:
        kind = "ZZ" if index_text.startswith("ZZ") else "Z"
        index = {"kind": kind, "number": int(index_text[len(kind):]), "access": "read"}
    device = {
        "family": family,
        "address_text": match.group("address"),
        "address": address,
        "display_radix": radix,
        "module": int(match.group("module")) if match.group("module") is not None else None,
        "word_bit": bit,
        "index": index,
        "indirect": match.group("indirect") is not None,
        "digit_width": int(match.group("digit")[1:]) if match.group("digit") else None,
        "unit": "bit" if family in BIT_FAMILIES and bit is None else "word",
    }
    return {**base, "kind": "device", "status": "decoded" if address is not None else "unknown",
            "device": device}


def _role(opcode: str, position: int, operand_count: int) -> tuple[str, str]:
    destination = legacy.dest_index(opcode, operand_count)
    if destination is None:
        if opcode.startswith("<"):
            return "unknown", "OPCODE_ACCESS_UNCLASSIFIED"
        if opcode in legacy.KNOWN_READ or opcode in legacy.NO_WRITE_CTRL or legacy.is_comparison(opcode):
            return "read", "READ_OR_CONTROL_INSTRUCTION"
        return "unknown", "OPCODE_ACCESS_UNCLASSIFIED"
    if position != destination:
        return "read", "OPERAND_POSITION"
    if opcode in RMW_DEST:
        return "both", "READ_MODIFY_WRITE_DESTINATION"
    return "write", "DESTINATION_OPERAND_POSITION"


def _range_width(opcode: str, position: int, operands: list[dict[str, Any]]) -> tuple[str, int | None, str]:
    if opcode in {"BMOV", "BMOVP"} and position in (0, 1):
        count = operands[2] if len(operands) > 2 else None
        if count and count["kind"] == "constant" and count["constant"]["notation"] == "K":
            value = count["constant"]["value"]
            return ("STATIC", value, "BMOV_K_COUNT") if isinstance(value, int) and value > 0 else ("UNKNOWN", None, "INVALID_COUNT")
        return "DYNAMIC", None, "COUNT_NOT_STATIC_K"
    if opcode in {"FMOV", "FMOVP"} and position == 1:
        count = operands[2] if len(operands) > 2 else None
        if count and count["kind"] == "constant" and count["constant"]["notation"] == "K":
            value = count["constant"]["value"]
            return ("STATIC", value, "FMOV_K_COUNT") if isinstance(value, int) and value > 0 else ("UNKNOWN", None, "INVALID_COUNT")
        return "DYNAMIC", None, "COUNT_NOT_STATIC_K"
    return "STATIC", 2 if opcode in DOUBLE_WORD else 1, "INSTRUCTION_WIDTH"


def _coverage(operand: dict[str, Any], opcode: str, operands: list[dict[str, Any]]) -> dict[str, Any]:
    if operand["kind"] != "device" or operand["status"] != "decoded":
        return {"state": "NOT_APPLICABLE", "word_width": None, "addresses": None, "reason": "NOT_DECODED_DEVICE"}
    device = operand["device"]
    state, width, reason = _range_width(opcode, operand["position"], operands)
    if device["index"] is not None or device["indirect"]:
        return {"state": "DYNAMIC", "word_width": width, "addresses": None,
                "reason": "INDEX_OR_INDIRECT_ADDRESS"}
    if state != "STATIC" or width is None:
        return {"state": state, "word_width": width, "addresses": None, "reason": reason}
    if width > MAX_COVERED_ADDRESSES:
        return {"state": "LIMIT_REACHED", "word_width": width, "addresses": None,
                "reason": "COVERED_ADDRESS_LIMIT"}
    addresses = []
    for offset in range(width):
        addresses.append({
            "family": device["family"],
            "address": device["address"] + offset,
            "module": device["module"],
            "word_bit": device["word_bit"],
            "offset": offset,
        })
    return {"state": "STATIC", "word_width": width, "addresses": addresses, "reason": reason}


def project_rows(pous: list[dict[str, Any]], *, input_sha256: str,
                 profile_id: str = "mitsubishi.gxw.q.ladder") -> dict[str, Any]:
    occurrences: list[dict[str, Any]] = []
    unknown_operands = 0
    total_operands = 0
    total_covered = 0
    for pou_order, pou in enumerate(pous):
        name = pou["name"]
        source_store = str(pou["source_store"])
        source_digest = str(pou["source_digest"])
        for sequence, row in enumerate(pou["rows"]):
            opcode, operand_text, comment = row
            if opcode in {"__STMT__", "__NOTE__"}:
                continue
            raw_tokens = operand_text.split() if operand_text else []
            operands = [parse_operand(token, position) for position, token in enumerate(raw_tokens)]
            total_operands += len(operands)
            if total_operands > MAX_OPERANDS:
                raise ReferenceIrError("OPERAND_LIMIT")
            for operand in operands:
                role, basis = _role(opcode, operand["position"], len(operands))
                operand["access"] = role
                operand["access_basis"] = basis
                operand["coverage"] = _coverage(operand, opcode, operands)
                addresses = operand["coverage"]["addresses"]
                total_covered += len(addresses) if isinstance(addresses, list) else 0
                if total_covered > MAX_TOTAL_COVERED_ADDRESSES:
                    raise ReferenceIrError("COVERED_ADDRESS_TOTAL_LIMIT")
                if operand["status"] != "decoded" or operand["access"] == "unknown":
                    unknown_operands += 1
            locator = f"_hdb/{source_store}:row:{sequence}"
            identity = f"{input_sha256}\0{name}\0{source_store}\0{sequence}\0{opcode}\0{operand_text}".encode("utf-8")
            occurrences.append({
                "occurrence_id": _sha256(identity),
                "pou": {"name": name, "order": pou_order,
                        "order_basis": pou.get("order_basis", "CALLER_INPUT_ORDER")},
                "record": {"sequence": sequence, "opcode": opcode},
                "provenance": {"source_store": source_store, "source_locator": locator,
                               "source_digest": source_digest},
                "comment": {"scope": "device", "language_slot": "legacy-default",
                            "state": "VALUE" if comment else "UNAVAILABLE", "value": comment or None},
                "operands": operands,
            })
            if len(occurrences) > MAX_OCCURRENCES:
                raise ReferenceIrError("OCCURRENCE_LIMIT")
    return {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "profile_id": profile_id,
        "input": {"sha256": input_sha256},
        "analysis": {"state": "PARTIAL" if unknown_operands else "COMPLETE",
                     "official_validation": "NOT_RUN", "production_adoption": "NOT_GRANTED"},
        "coverage": {"occurrences": len(occurrences), "operands": total_operands,
                     "decoded_operands": total_operands - unknown_operands,
                     "unknown_operands": unknown_operands},
        "occurrences": occurrences,
    }


def build(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ReferenceIrError("INPUT_NOT_REGULAR_FILE")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ReferenceIrError("INPUT_CAP")
    before = path.read_bytes()
    if len(before) > MAX_INPUT_BYTES:
        raise ReferenceIrError("INPUT_CAP")
    input_sha = _sha256(before)
    streams = reader.load_all_substreams(str(path))
    pous, cmap, registry = reader.collect_pous(streams)
    source_pous = []
    registry_names = [name for name in registry[2] if name in pous] if registry else []
    ordered_names = registry_names + sorted(set(pous) - set(registry_names))
    order_basis = "REGISTRY_ORDER" if registry else "NAME_SORT_FALLBACK"
    for name in ordered_names:
        source_store, body, _score = pous[name]
        sec0 = re.split(rb"\x34\x02\x04", body, maxsplit=1)[0]
        rows, _unknown_i, _unknown_d = reader.pou_rows(body, cmap)
        source_pous.append({"name": name, "source_store": source_store, "order_basis": order_basis,
                            "source_digest": _sha256(sec0), "rows": rows})
    after = path.read_bytes()
    if len(after) > MAX_INPUT_BYTES:
        raise ReferenceIrError("INPUT_CAP")
    if _sha256(after) != input_sha or after != before:
        raise ReferenceIrError("INPUT_CHANGED_DURING_ANALYSIS")
    return project_rows(source_pous, input_sha256=input_sha)


def _publish_new(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ReferenceIrError("OUTPUT_PARENT")
    if path.exists() or path.is_symlink():
        raise ReferenceIrError("OUTPUT_EXISTS")
    if len(payload) > MAX_OUTPUT_BYTES:
        raise ReferenceIrError("OUTPUT_CAP")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except FileExistsError as error:
        raise ReferenceIrError("OUTPUT_EXISTS") from error
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build(args.source)
        payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _publish_new(args.output, payload)
    except ReferenceIrError as error:
        print(json.dumps({"analysis": "BLOCKED", "reason": str(error)}, sort_keys=True))
        return 1
    except (OSError, ValueError):
        print(json.dumps({"analysis": "BLOCKED", "reason": "REFERENCE_IR_IO_OR_SCHEMA"}, sort_keys=True))
        return 1
    print(json.dumps({"analysis": report["analysis"]["state"],
                      "occurrences": report["coverage"]["occurrences"],
                      "official_validation": "NOT_RUN"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
