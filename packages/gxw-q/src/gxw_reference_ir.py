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
import math
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
HEX_FAMILIES = {"X", "Y", "DY", "B", "W", "SB", "SW"}
BIT_FAMILIES = {"X", "Y", "DY", "M", "L", "F", "B", "SM", "SB", "T", "ST", "C"}
RMW_DEST = {"INC", "INCP", "DINC", "DINCP", "DEC", "DECP", "DDEC", "DDECP",
            "DNEG", "SFL", "SFR", "SFT", "SFTP", "BSFL", "BSFR"}
DOUBLE_WORD = {"DMOV", "DMOVP", "D+", "D-", "D*", "D/", "DAND", "DOR", "DXOR",
               "DINC", "DINCP", "DDEC", "DDECP", "DNEG"}
DEVICE = re.compile(
    r"^(?P<indirect>@)?(?:(?P<digit>K[1-8]))?(?:U(?P<module>[0-9A-F]+)\\)?"
    r"(?P<family>ZR|SM|SD|FD|SB|SW|ST|DY|X|Y|M|L|F|B|D|R|W|T|C|Z|G)"
    r"(?P<address>[0-9A-F]+)(?P<index>ZZ?[0-9]+)?(?:\.(?P<bit>[0-9A-F]+))?$"
)
CONSTANT = re.compile(r"^(?P<kind>K|H|E)(?P<value>.+)$")
CONTROL = re.compile(r"^(?P<kind>N|P)(?P<address>[0-9]+)$")
INDEXED_K = re.compile(r"^K(?P<value>-?[0-9]+)Z(?P<index>[0-9]+)$")
_CONTROL_READ_FORMS = frozenset({("N", "MC", 0, 2), ("N", "MCR", 0, 1),
                                 ("P", "CALL", 0, 1), ("P", "XCALL", 0, 1)})
# MELSEC-Q/L Programming Manual (Common Instruction), SH-080809ENG, 5.1:
# each (S) of these contact instructions is a source bit device.
_CONTACT_READ = frozenset({"LDFI", "ANDF", "ORPI", "ORFI"})
# SH-080809ENG-X observed spellings only: (access, span). A span is a
# word count, runtime string, count operand, bit result, or reserved workspace.
# No suffix/P variants, implicit SM flags, CPU capability or runtime claims.
_MINED_FORMS = {
    "SUM": {2: (("read", 1), ("write", 1))},
    "SEG": {2: (("read", 1), ("write", 1))},
    "SER": {4: (("read", 1), ("read", "count:3"), ("write", 2), ("read", 1))},
    "UNI": {3: (("read", "uni:2"), ("write", 1), ("read", 1))},
    "WSUM": {3: (("read", "count:2"), ("write", 2), ("read", 1))},
    "DBCD": {2: (("read", 2), ("write", 2))},
    "DXOR": {2: (("read", 2), ("both", 2)), 3: (("read", 2), ("read", 2), ("write", 2))},
    "DZCP": {4: (("read", 2), ("read", 2), ("read", 2), ("write", "bits:3"))},
    "$+": {2: (("read", "string"), ("both", "string")),
           3: (("read", "string"), ("read", "string"), ("write", "string"))},
    "LEN": {2: (("read", "string"), ("write", 1))},
    "SORT": {5: (("both", "count:1"), ("read", 1), ("read", 1),
                 ("write", "bits:1"), ("unknown", "reserved:2"))},
}


class ReferenceIrError(ValueError):
    pass


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _parse_int(text: str, radix: int) -> int | None:
    try:
        return int(text, radix)
    except ValueError:
        return None


def split_operands(operand_text: str) -> list[str]:
    """Keep quoted source literals intact while retaining each raw token.

    Quote or escape dialects beyond one paired double quote are unverified.
    Unmatched quotes keep the remaining text in one token, which parse_operand
    marks unknown rather than interpreting its contents as separate devices.
    """
    tokens: list[str] = []
    start: int | None = None
    quoted = False
    for index, char in enumerate(operand_text):
        if char.isspace() and not quoted:
            if start is not None:
                tokens.append(operand_text[start:index])
                start = None
            continue
        if start is None:
            start = index
        if char == '"':
            quoted = not quoted
    if start is not None:
        tokens.append(operand_text[start:])
    return tokens


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
    if raw_token.startswith('"') and raw_token.endswith('"') and raw_token.count('"') == 2:
        return {**base, "kind": "literal", "status": "decoded"}
    control = CONTROL.fullmatch(raw_token)
    if control:
        return {**base, "kind": "control", "status": "decoded"}
    indexed_k = INDEXED_K.fullmatch(raw_token)
    if indexed_k:
        value = _parse_int(indexed_k.group("value"), 10)
        index_number = _parse_int(indexed_k.group("index"), 10)
        if value is None or index_number is None:
            return base
        return {**base, "kind": "constant", "status": "decoded",
                "constant": {"notation": "K", "value": value,
                             "index": {"kind": "Z", "number": index_number, "access": "read"}}}
    match = DEVICE.fullmatch(raw_token)
    if not match:
        constant = CONSTANT.fullmatch(raw_token)
        if constant:
            radix = 16 if constant.group("kind") == "H" else 10
            value = _parse_int(constant.group("value"), radix)
            if constant.group("kind") == "E":
                try:
                    spelling = constant.group("value")
                    if re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", spelling) is None:
                        raise ValueError("invalid floating constant spelling")
                    value = float(spelling)
                    if not math.isfinite(value):
                        value = None
                except ValueError:
                    value = None
            return {**base, "kind": "constant", "status": "decoded" if value is not None else "unknown",
                    "constant": {"notation": constant.group("kind"), "value": value}}
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
        "module": int(match.group("module"), 16) if match.group("module") is not None else None,
        "word_bit": bit,
        "index": index,
        "indirect": match.group("indirect") is not None,
        "digit_width": int(match.group("digit")[1:]) if match.group("digit") else None,
        "unit": "bit" if family in BIT_FAMILIES and bit is None else "word",
    }
    return {**base, "kind": "device", "status": "decoded" if address is not None else "unknown",
            "device": device}


def _role(opcode: str, position: int, operand_count: int) -> tuple[str, str]:
    if opcode in _MINED_FORMS:
        form = _MINED_FORMS[opcode].get(operand_count)
        if form is None:
            return "unknown", "MINED_FORM_ARITY_UNVERIFIED"
        return form[position][0], ("RESERVED_WORKSPACE_ACCESS_UNVERIFIED" if opcode == "SORT" and position == 4
                                   else "MANUAL_OPERAND_ROLE")
    if opcode in _SOCKET_DUMMY_ARITY:
        return "unknown", "SOCKET_CONTEXT_UNVERIFIED"
    if opcode in _CONTACT_READ:
        return (("read", "CONTACT_SOURCE_DEVICE") if position == 0 and operand_count == 1 else
                ("unknown", "CONTACT_FORM_UNVERIFIED"))
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


_SOCKET_DUMMY_ARITY = {"SP.SOCOPEN": 4, "SP.SOCCLOSE": 4, "SP.SOCRCV": 5, "SP.SOCSND": 5}


def _instruction_operands(opcode: str, tokens: list[str], profile_id: str) -> list[dict[str, Any]]:
    operands = [parse_operand(token, position) for position, token in enumerate(tokens)]
    # SH-080811ENG-X sections 7.4.1/2/3/5 define this exact first argument
    # as a dummy character string. Bare U0 is not a generic device family.
    if (profile_id == "mitsubishi.gxw.q.ladder" and tokens and tokens[0] == "U0"
            and len(tokens) == _SOCKET_DUMMY_ARITY.get(opcode)):
        operands[0].update(kind="literal", status="decoded")
    return operands


def _socket_context(opcode: str, operands: list[dict[str, Any]]) -> bool:
    return (len(operands) == _SOCKET_DUMMY_ARITY.get(opcode) and bool(operands) and
            operands[0]["kind"] == "literal" and operands[0]["raw_token"] == "U0")


def _observed_role(operand: dict[str, Any], opcode: str, operand_count: int,
                   operands: list[dict[str, Any]] | None = None) -> tuple[str, str]:
    position = operand["position"]
    if opcode in _SOCKET_DUMMY_ARITY and operands is not None and _socket_context(opcode, operands):
        if position == 0:
            return "read", "SOCKET_DUMMY_LITERAL"
        roles = ("read", "read", "both" if opcode == "SP.SOCOPEN" else "write")
        role = roles[position] if position < 3 else ("write" if position == operand_count - 1 else
                                                   "read" if opcode == "SP.SOCSND" else "write")
        basis = "SOCKET_MANUAL_OPERAND_ROLE"
    else:
        role, basis = _role(opcode, position, operand_count)
    if ((opcode in _MINED_FORMS or opcode in _SOCKET_DUMMY_ARITY) and
            role in {"write", "both"} and operand["kind"] != "device"):
        return "unknown", "MINED_WRITE_TARGET_UNVERIFIED"
    if operand["kind"] == "control":
        form = (operand["raw_token"][0], opcode, operand["position"], operand_count)
        return (("read", "OBSERVED_CONTROL_READ_FORM") if form in _CONTROL_READ_FORMS else
                ("unknown", "CONTROL_ACCESS_UNVERIFIED"))
    if (operand["kind"] == "constant" and operand["constant"].get("index") is not None
            and role in {"write", "both"}):
        return "unknown", "INDEXED_CONSTANT_WRITE_UNSUPPORTED"
    return role, basis


def _range_width(opcode: str, position: int, operands: list[dict[str, Any]]) -> tuple[str, int | None, str]:
    if opcode in _SOCKET_DUMMY_ARITY:
        if not _socket_context(opcode, operands):
            return "UNKNOWN", None, "SOCKET_CONTEXT_UNVERIFIED"
        if position == 2:
            return "UNKNOWN", None, "RESERVED_OR_MIXED_CONTROL_BLOCK"
        if position == len(operands) - 1:
            return "STATIC", 2, "BIT_RESULT_SPAN"
        if position == 3:
            return "DYNAMIC", None, "SOCKET_RUNTIME_PAYLOAD_LENGTH"
        return "STATIC", 1, "MANUAL_WORD_SPAN"
    if opcode in _MINED_FORMS:
        form = _MINED_FORMS[opcode].get(len(operands))
        if form is None:
            return "UNKNOWN", None, "MINED_FORM_ARITY_UNVERIFIED"
        span = form[position][1]
        if isinstance(span, int):
            return "STATIC", span, "MANUAL_WORD_SPAN"
        if span == "string":
            return "DYNAMIC", None, "RUNTIME_NULL_TERMINATED_STRING"
        kind, number = span.split(":")
        if kind == "bits":
            return "STATIC", int(number), "BIT_RESULT_SPAN"
        if kind == "reserved":
            return "STATIC", int(number), "RESERVED_WORKSPACE_ACCESS_UNVERIFIED"
        count = operands[int(number)]
        # Only a positive plain decimal K spelling is a static count.
        if (count["kind"] == "constant" and re.fullmatch(r"K-?[0-9]+", count["raw_token"]) and
                count["constant"].get("index") is None and type(count["constant"]["value"]) is int):
            value = count["constant"]["value"]
            if value <= 0 or (kind == "uni" and value > 4):
                return "UNKNOWN", None, "INVALID_OR_NOOP_COUNT"
            return "STATIC", value, "MANUAL_K_COUNT"
        return "DYNAMIC", None, "COUNT_NOT_STATIC_K"
    if opcode in {"BMOV", "BMOVP"} and position in (0, 1):
        count = operands[2] if len(operands) > 2 else None
        if (count and count["kind"] == "constant" and count["constant"]["notation"] == "K"
                and count["constant"].get("index") is None):
            value = count["constant"]["value"]
            return ("STATIC", value, "BMOV_K_COUNT") if isinstance(value, int) and value > 0 else ("UNKNOWN", None, "INVALID_COUNT")
        return "DYNAMIC", None, "COUNT_NOT_STATIC_K"
    if opcode in {"FMOV", "FMOVP"} and position == 1:
        count = operands[2] if len(operands) > 2 else None
        if (count and count["kind"] == "constant" and count["constant"]["notation"] == "K"
                and count["constant"].get("index") is None):
            value = count["constant"]["value"]
            return ("STATIC", value, "FMOV_K_COUNT") if isinstance(value, int) and value > 0 else ("UNKNOWN", None, "INVALID_COUNT")
        return "DYNAMIC", None, "COUNT_NOT_STATIC_K"
    return "STATIC", 2 if opcode in DOUBLE_WORD else 1, "INSTRUCTION_WIDTH"


def _coverage(operand: dict[str, Any], opcode: str, operands: list[dict[str, Any]]) -> dict[str, Any]:
    mined = opcode in _MINED_FORMS or opcode in _SOCKET_DUMMY_ARITY
    if mined:
        if (operand["kind"] != "device" and
                _observed_role(operand, opcode, len(operands), operands)[1] == "MINED_WRITE_TARGET_UNVERIFIED"):
            return {"state": "UNKNOWN", "word_width": None, "addresses": None,
                    "reason": "MINED_WRITE_TARGET_UNVERIFIED"}
        state, width, reason = _range_width(opcode, operand["position"], operands)
        if reason in {"MINED_FORM_ARITY_UNVERIFIED", "SOCKET_CONTEXT_UNVERIFIED"}:
            return {"state": "UNKNOWN", "word_width": None, "addresses": None, "reason": reason}
        if reason == "BIT_RESULT_SPAN" and operand["kind"] != "device":
            return {"state": "UNKNOWN", "word_width": None, "addresses": None, "reason": "BIT_RESULT_FORM_UNVERIFIED"}
        if reason == "RESERVED_OR_MIXED_CONTROL_BLOCK":
            return {"state": "UNKNOWN", "word_width": None, "addresses": None, "reason": reason}
    if operand["kind"] == "constant" and operand["constant"].get("index") is not None:
        return {"state": "DYNAMIC", "word_width": None, "addresses": None,
                "reason": "INDEXED_CONSTANT_ADDRESS"}
    if operand["kind"] != "device" or operand["status"] != "decoded":
        return {"state": "NOT_APPLICABLE", "word_width": None, "addresses": None, "reason": "NOT_DECODED_DEVICE"}
    device = operand["device"]
    state, width, reason = _range_width(opcode, operand["position"], operands)
    bit_result = reason == "BIT_RESULT_SPAN"
    if bit_result and (device["family"] != "M" or device["word_bit"] is not None or
                       device["digit_width"] is not None or device["module"] is not None):
        return {"state": "UNKNOWN", "word_width": None, "addresses": None, "reason": "BIT_RESULT_FORM_UNVERIFIED"}
    if device["index"] is not None or device["indirect"]:
        return {"state": "DYNAMIC", "word_width": None if bit_result else width, "addresses": None,
                "reason": "INDEX_OR_INDIRECT_ADDRESS"}
    digit_width = device["digit_width"]
    if mined and bit_result:
        return {"state": "STATIC", "word_width": None, "addresses": [
            {"family": device["family"], "address": device["address"] + offset,
             "module": None, "word_bit": None, "offset": offset} for offset in range(width)],
                "reason": "BIT_RESULT_SPAN"}
    if mined and (device["unit"] != "word" or device["word_bit"] is not None or digit_width is not None):
        if not (opcode == "SUM" and operand["position"] == 0 and digit_width is not None):
            return {"state": "UNKNOWN", "word_width": width, "addresses": None, "reason": "MINED_WORD_DEVICE_FORM_UNVERIFIED"}
    if state != "STATIC" or width is None:
        return {"state": state, "word_width": width, "addresses": None, "reason": reason}
    if digit_width is not None:
        if device["family"] not in BIT_FAMILIES or device["word_bit"] is not None:
            return {"state": "UNKNOWN", "word_width": width, "addresses": None,
                    "reason": "DIGIT_DEVICE_FORM_UNVERIFIED"}
        if opcode in {"BMOV", "BMOVP", "FMOV", "FMOVP"}:
            return {"state": "UNKNOWN", "word_width": width, "addresses": None,
                    "reason": "DIGIT_BLOCK_SPAN_UNVERIFIED"}
        count = 4 * digit_width
        addresses = [{"family": device["family"], "address": device["address"] + offset,
                      "module": device["module"], "word_bit": device["word_bit"], "offset": offset}
                     for offset in range(count)]
        return {"state": "STATIC", "word_width": width, "addresses": addresses,
                "reason": "DIGIT_BIT_WIDTH"}
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
    diagnostics: list[dict[str, Any]] = []
    unknown_instructions = 0
    unknown_operands = 0
    total_operands = 0
    total_covered = 0
    incomplete_ranges = False
    for pou_order, pou in enumerate(pous):
        name = pou["name"]
        source_store = str(pou["source_store"])
        source_digest = str(pou["source_digest"])
        instruction_findings = set(pou.get("unknown_instructions", ()))
        instruction_findings.update(row[0] for row in pou["rows"] if row[0].startswith("<"))
        unknown_instructions += sum(row[0].startswith("<") for row in pou["rows"])
        if instruction_findings and not any(row[0].startswith("<") for row in pou["rows"]):
            unknown_instructions += len(instruction_findings)
        for kind, findings in (("instruction", instruction_findings),
                               ("operand", set(pou.get("unknown_devices", ())))):
            for finding in sorted(findings):
                diagnostics.append({"pou": name, "source_store": source_store,
                                    "kind": kind, "raw_token": finding})
        for sequence, row in enumerate(pou["rows"]):
            opcode, operand_text, comment = row
            if opcode in {"__STMT__", "__NOTE__"}:
                continue
            raw_tokens = split_operands(operand_text) if operand_text else []
            operands = _instruction_operands(opcode, raw_tokens, profile_id)
            form_reason = ("MINED_FORM_ARITY_UNVERIFIED" if opcode in _MINED_FORMS and len(operands) not in _MINED_FORMS[opcode]
                           else "SOCKET_CONTEXT_UNVERIFIED" if opcode in _SOCKET_DUMMY_ARITY and not _socket_context(opcode, operands)
                           else None)
            if form_reason:
                incomplete_ranges = True
                diagnostics.append({"pou": name, "source_store": source_store, "row": sequence,
                                    "source_locator": f"_hdb/{source_store}:row:{sequence}",
                                    "kind": "instruction", "raw_token": opcode, "reason": form_reason})
            total_operands += len(operands)
            if total_operands > MAX_OPERANDS:
                raise ReferenceIrError("OPERAND_LIMIT")
            for operand in operands:
                role, basis = _observed_role(operand, opcode, len(operands), operands)
                operand["access"] = role
                operand["access_basis"] = basis
                operand["coverage"] = _coverage(operand, opcode, operands)
                if operand["coverage"]["state"] in {"UNKNOWN", "DYNAMIC", "LIMIT_REACHED"}:
                    incomplete_ranges = True
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
        "analysis": {"state": "PARTIAL" if unknown_operands or diagnostics or unknown_instructions or incomplete_ranges else "COMPLETE",
                     "official_validation": "NOT_RUN", "production_adoption": "NOT_GRANTED"},
        "coverage": {"occurrences": len(occurrences), "operands": total_operands,
                     "decoded_operands": total_operands - unknown_operands,
                     "unknown_operands": unknown_operands,
                     "unknown_instructions": unknown_instructions},
        "diagnostics": diagnostics,
        "occurrences": occurrences,
    }


def build(path: Path, *, text_encoding: str = "cp1252") -> dict[str, Any]:
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
        sec0 = reader.program_section(body)
        rows, _unknown_i, _unknown_d = reader.pou_rows(body, cmap, text_encoding=text_encoding)
        source_pous.append({"name": name, "source_store": source_store, "order_basis": order_basis,
                            "source_digest": _sha256(sec0), "rows": rows,
                            "unknown_instructions": sorted(_unknown_i),
                            "unknown_devices": sorted(_unknown_d)})
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
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--text-encoding", choices=("cp1252", "cp949", "auto"), default="cp1252")
    args = parser.parse_args(argv)
    try:
        report = build(args.source, text_encoding=args.text_encoding)
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
