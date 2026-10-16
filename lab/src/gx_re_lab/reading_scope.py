"""Additive GX3 reading-scope projection; no archive or setting-byte reads.

Input: Neutral IR 1.0.0 dict; entries: list[{name: str, sha256: lowercase
hex64, byte_count: nonnegative int}]. The caller verifies archive metadata.
Output: JSON-compatible report with copied identity/profile/findings/coverage,
sorted entry observations and missing-category diagnostics. Coverage describes
IR entities only, never a denominator of project bytes or settings semantics.
Dependencies: standard library and the existing Lab Neutral IR validator.
"""
from __future__ import annotations

from copy import deepcopy
from importlib import resources
import json
import math
import re

from .explorer_diff import ExplorerDiffError, _validate_neutral_root

FORMAT = "plcman.gx-re-lab.reading-scope"
MAX_ENTRIES = 10_000
MAX_NODES = 1_000_000
REASONS = {
    "cpu_parameters": "CPU.PRM settings bytes and CPU program registration/execution types are not decoded here.",
    "unit_parameters": "UNIT.PRM module settings bytes are not decoded here.",
    "w3pa": "w3pa settings semantics are not decoded here.",
    "program_container": "Program.qpg topology references do not decode CPU program registration or execution types.",
    "pou_link_order": "PouLinkOrder expresses observed POU ordering, not CPU registration or execution types.",
    "pcode": "IR record provenance is a projection; complete pcode byte/semantic coverage is not established.",
    "project_metadata": "_Project.txc project settings semantics are not decoded here.",
    "unknown": "Unclassified archive entry; semantic coverage is unknown.",
}


class ReadingScopeError(ValueError):
    """Stable machine-readable failure code; no source content in errors."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReadingScopeError(code)


def _bounded_json(value: object) -> None:
    # Bound work before invoking recursive copying; cycles reach the depth cap.
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        _require(nodes <= MAX_NODES and depth <= 32, "INPUT_LIMIT")
        if isinstance(item, dict):
            _require(len(item) <= MAX_NODES, "INPUT_LIMIT")
            for key, child in item.items():
                _require(isinstance(key, str), "JSON_SCHEMA")
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            _require(len(item) <= MAX_NODES, "INPUT_LIMIT")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            _require(len(item) <= 65_536 and not any(0xD800 <= ord(c) <= 0xDFFF for c in item), "TEXT_SCHEMA")
        else:
            _require(item is None or type(item) in (bool, int, float), "JSON_SCHEMA")
            _require(type(item) is not float or math.isfinite(item), "JSON_SCHEMA")
        _require(len(stack) <= MAX_NODES, "INPUT_LIMIT")


def _category(name: str) -> str:
    base = name.rsplit("/", 1)[-1].casefold()
    exact = {"cpu.prm": "cpu_parameters", "unit.prm": "unit_parameters",
             "program.qpg": "program_container", "poulinkorder.info": "pou_link_order",
             "_project.txc": "project_metadata", "w3pa": "w3pa", "pcode": "pcode"}
    if base in exact:
        return exact[base]
    if base.endswith(".w3pa"):
        return "w3pa"
    if base.endswith(".pcode"):
        return "pcode"
    return "unknown"


def build_reading_scope(ir: dict, entries: list[dict]) -> dict:
    """Report unsupported GX3 project semantics; never authorize PLC use.

    Entry inventory is caller-supplied, not independently verified here. Unknown
    formats/profiles fail explicitly; missing category observations stay PARTIAL.
    """
    _require(isinstance(ir, dict), "IR_SCHEMA")
    _bounded_json(ir)
    _require(ir.get("schema_name") == "plcman.gx3.neutral-ir", "UNSUPPORTED_FORMAT")
    profile = ir.get("profile")
    _require(isinstance(profile, dict), "IR_SCHEMA")
    packages = {"mitsubishi.gx3.fx5u.ladder": "gx3_fx5_parser_toolkit",
                "mitsubishi.gx3.r04cpu.ladder": "gx3_r_parser_toolkit"}
    _require(isinstance(profile.get("profile_id"), str) and profile["profile_id"] in packages, "UNSUPPORTED_PROFILE")
    from gx3_r_parser_toolkit.schema_validator import validate
    schema = json.loads(resources.files(packages[profile["profile_id"]]).joinpath(
        "schemas/neutral-ir-1.0.0.schema.json").read_text(encoding="utf-8"))
    try:
        validate(ir, schema)
        _validate_neutral_root(ir)
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise ReadingScopeError("IR_SCHEMA") from exc
    _require(profile["detector_status"] in {"SUPPORTED", "UNSUPPORTED", "AMBIGUOUS"}, "IR_SCHEMA")
    identity = ir["input"]
    _require(set(identity) == {"display_id", "sha256", "byte_count", "read_only_unchanged"} and
             isinstance(identity["display_id"], str) and
             isinstance(identity["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]) is not None and
             type(identity["byte_count"]) is int and identity["byte_count"] >= 0 and
             type(identity["read_only_unchanged"]) is bool, "IDENTITY_SCHEMA")
    for counts in ir["coverage"].values():
        _require(counts["total"] == sum(counts[k] for k in ("decoded", "partial", "unknown")), "COVERAGE_SCHEMA")
    _require(isinstance(entries, list) and len(entries) <= MAX_ENTRIES, "ENTRY_SCHEMA")
    observed = {}
    for entry in entries:
        _require(isinstance(entry, dict) and set(entry) == {"name", "sha256", "byte_count"}, "ENTRY_SCHEMA")
        name, digest, size = entry["name"], entry["sha256"], entry["byte_count"]
        _require(isinstance(name, str) and 0 < len(name) <= 4096 and
                 not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name) and
                 not any(c in name for c in "\\:") and
                 all(part not in {"", ".", ".."} for part in name.split("/")), "ENTRY_NAME")
        _require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None and
                 type(size) is int and size >= 0, "ENTRY_FINGERPRINT")
        _require(name.casefold() not in observed, "DUPLICATE_ENTRY")
        observed[name.casefold()] = deepcopy(entry)
    # Source digests can identify rows/blocks rather than whole archive entries.
    # Bind names only; do not invent a digest mismatch or a byte coverage claim.
    locations: dict[str, list[str]] = {}
    mismatches = []
    names = {entry["name"] for entry in observed.values()}
    for f, finding in enumerate(ir["findings"]):
        if finding["locator"] in names:
            locations.setdefault(finding["locator"], []).append(f"/findings/{f}")
    for p, pou in enumerate(ir["pous"]):
        for f, finding in enumerate(pou["findings"]):
            if finding["locator"] in names:
                locations.setdefault(finding["locator"], []).append(f"/pous/{p}/findings/{f}")
        for rel, name in enumerate(pou["relations"]):
            if isinstance(name, str) and name.casefold() in observed and observed[name.casefold()]["name"] == name:
                locations.setdefault(name, []).append(f"/pous/{p}/relations/{rel}")
            else:
                mismatches.append({"code": "UNBOUND_IR_RELATION", "ir_location": f"/pous/{p}/relations/{rel}", "entry": name})
    stack = [(ir, "")]
    while stack:
        value, pointer = stack.pop()
        if isinstance(value, dict) and {"source_entry", "source_store", "source_locator", "source_digest"} <= value.keys():
            name = value["source_entry"]
            entry = observed.get(name.casefold())
            if entry is None or entry["name"] != name:
                mismatches.append({"code": "UNBOUND_IR_PROVENANCE", "ir_location": pointer, "entry": name})
            else:
                locations.setdefault(name, []).append(pointer)
        if isinstance(value, dict):
            stack.extend((child, pointer + "/" + key.replace("~", "~0").replace("/", "~1")) for key, child in value.items())
        elif isinstance(value, list):
            stack.extend((child, pointer + "/" + str(i)) for i, child in enumerate(value))
    rows = []
    for entry in sorted(observed.values(), key=lambda x: x["name"]):
        category = _category(entry["name"])
        rows.append({**entry, "category": category, "entry_location": entry["name"],
                     "ir_locations": sorted(locations.get(entry["name"], [])),
                     "source_coverage": "METADATA_OBSERVED", "semantic_status": "NOT_ESTABLISHED",
                     "reason": REASONS[category]})
    categories = {row["category"] for row in rows}
    diagnostics = [{"code": "MISSING_REQUIRED_CATEGORY", "category": category,
                    "reason": "Required for this report's inventory checklist; not proof of archive invalidity."}
                   for category in sorted(set(REASONS) - {"unknown"} - categories)]
    diagnostics.extend({"code": "UNKNOWN_ENTRY_CATEGORY", "entry": row["name"]}
                       for row in rows if row["category"] == "unknown")
    diagnostics.extend(sorted(mismatches, key=lambda d: d["ir_location"]))
    return {"format": FORMAT, "version": 1, "scope": "GX3_UNSUPPORTED_SEMANTICS_REPORT",
            "decision": "PARTIAL", "project_reading_complete": False,
            "support_claim": "NOT_MADE", "plc_execution": "NOT_RUN",
            "input_identity": deepcopy(ir["input"]), "profile": deepcopy(profile),
            "ir_findings": deepcopy(ir["findings"]), "ir_coverage": deepcopy(ir["coverage"]),
            "ir_pou_findings": [{"ir_location": f"/pous/{p}/findings", "findings": deepcopy(pou["findings"])}
                                for p, pou in enumerate(ir["pous"]) if pou["findings"]],
            "source_coverage": {"status": "NOT_MEASURED", "denominator": None,
                                "inventory_authority": "CALLER_SUPPLIED", "archive_binding_verified": False,
                                "provenance_digest_scope": "NOT_ASSUMED_TO_BE_WHOLE_ENTRY"},
            "entries": rows, "diagnostics": diagnostics}
