"""Phase 2 readiness acceptance harness."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from gx3_core.archive import ArchiveBudget

from .ir import build_neutral_ir, validate_ir
from .official_export import read_comment_tsv, read_label_tsv, read_ladder_tsv

_MAX_INPUT_BYTES = ArchiveBudget().max_input_bytes
_MAX_EVIDENCE_BYTES = ArchiveBudget().max_total_bytes


def _fingerprint(source: Path) -> tuple[int, str]:
    size = source.stat().st_size
    if size > _MAX_INPUT_BYTES:
        raise ValueError("GX3 input exceeds the configured byte budget")
    digest = hashlib.sha256()
    byte_count = 0
    with source.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            byte_count += len(chunk)
            if byte_count > _MAX_INPUT_BYTES:
                raise ValueError("GX3 input exceeded the configured byte budget")
            digest.update(chunk)
    if byte_count != size:
        raise ValueError("GX3 input size changed while fingerprinting")
    return byte_count, digest.hexdigest()


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _redact_finding(item: dict[str, Any]) -> dict[str, str]:
    scope_class = str(item.get("scope", "")).partition(":")[0]
    return {
        "digest": str(item.get("digest", "")),
        "finding_code": str(item.get("finding_code", "")),
        "object_kind": str(item.get("object_kind", "")),
        "scope": scope_class,
    }


def _collect_findings(ir: dict[str, Any]) -> list[dict[str, str]]:
    items = [_redact_finding(item) for item in ir["findings"]]
    for pou in ir["pous"]:
        items.extend(_redact_finding(item) for item in pou["findings"])
    return sorted(
        items,
        key=lambda item: (
            item["finding_code"],
            item["scope"],
            item["object_kind"],
            item["digest"],
        ),
    )


def _blockers(
    detector_status: str,
    coverage: dict[str, Any],
    findings: list[dict[str, str]],
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    if detector_status != "SUPPORTED":
        blockers.append({"code": f"DETECTOR_{detector_status}", "count": 1})
    partial = sum(int(row["partial"]) for row in coverage.values())
    unknown = sum(int(row["unknown"]) for row in coverage.values())
    if partial:
        blockers.append({"code": "COVERAGE_PARTIAL", "count": partial})
    if unknown:
        blockers.append({"code": "COVERAGE_UNKNOWN", "count": unknown})
    for code, count in sorted(Counter(item["finding_code"] for item in findings).items()):
        blockers.append({"code": code, "count": count})
    return sorted(blockers, key=lambda item: (item["code"], item["count"]))


def evaluate_acceptance(source: Path) -> dict[str, Any]:
    """Build Neutral IR twice and return a privacy-safe Phase 2 readiness report."""
    before = _fingerprint(source)
    first = build_neutral_ir(source)
    mid = _fingerprint(source)
    second = build_neutral_ir(source)
    after = _fingerprint(source)
    if before != mid or mid != after:
        raise ValueError("source SHA-256 or byte count changed during acceptance")
    byte_count, sha256 = before
    if (
        first["input"]["byte_count"] != byte_count
        or second["input"]["byte_count"] != byte_count
        or first["input"]["sha256"] != sha256
        or second["input"]["sha256"] != sha256
    ):
        raise ValueError("source SHA-256 or byte count changed during acceptance")
    validate_ir(first)
    validate_ir(second)
    if _canonical(first) != _canonical(second):
        raise ValueError("canonical IR is not byte-identical")
    detector_status = str(first["profile"]["detector_status"])
    coverage = first["coverage"]
    findings = _collect_findings(first)
    reader_blockers = _blockers(detector_status, coverage, findings)
    reader_coverage_decision = "FULL" if not reader_blockers else "BLOCKED"
    readiness_blockers = [
        *reader_blockers,
        {"code": "INDEPENDENT_GX3_SET_REQUIRED", "count": 3},
        {"code": "JSON_SCHEMA_VALIDATION_REQUIRED", "count": 1},
        {"code": "OFFICIAL_EXPORT_COMPARISON_REQUIRED", "count": 1},
    ]
    return {
        "canonical_ir_identical": True,
        "coverage": coverage,
        "coverage_conserved": True,
        "decision": "BLOCKED",
        "detector_status": detector_status,
        "findings": findings,
        "format": "plcman.gx3.phase2-acceptance",
        "input": {
            "byte_count": byte_count,
            "sha256": sha256,
            "unchanged": True,
        },
        "official_export_compared": False,
        "independent_gx3_set_verified": False,
        "json_schema_validated": False,
        "phase2_closed": False,
        "reader_coverage_decision": reader_coverage_decision,
        "readiness_blockers": sorted(
            readiness_blockers, key=lambda item: (item["code"], item["count"])
        ),
        "version": "1.0.0",
    }


def _safe_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or path.drive or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"{label} must be a safe relative path")
    return path


def _within(root: Path, relative: object, label: str) -> Path:
    path = root / _safe_relative(relative, label)
    for ancestor in (path, *path.parents):
        if ancestor == root.parent:
            break
        if ancestor.exists() and ancestor.is_symlink():
            raise ValueError(f"{label} must not traverse a symlink")
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError(f"{label} escapes the manifest directory") from error
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} must name a regular file")
    return resolved


def _expect_fingerprint(value: object, path: Path, label: str) -> tuple[int, str]:
    if not isinstance(value, dict) or set(value) != {"byte_count", "sha256"}:
        raise ValueError(f"{label} fingerprint requires byte_count and sha256")
    count, digest = _fingerprint(path)
    if value.get("byte_count") != count or value.get("sha256") != digest:
        raise ValueError(f"{label} SHA-256 or byte count differs from manifest")
    return count, digest


def _resolve_ref(root: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ValueError("only local JSON Schema references are supported")
    value: Any = root
    for token in reference[2:].split("/"):
        if not isinstance(value, dict) or token not in value:
            raise ValueError("JSON Schema reference is unresolved")
        value = value[token]
    return value


def _schema_validate(value: Any, schema: dict[str, Any], root: dict[str, Any], location: str = "$") -> None:
    """Validate the checked-in schema's standard keyword subset using only stdlib."""
    if "$ref" in schema:
        target = _resolve_ref(root, str(schema["$ref"]))
        if not isinstance(target, dict):
            raise ValueError("JSON Schema reference target is not an object")
        _schema_validate(value, target, root, location)
        return
    if "not" in schema:
        try:
            _schema_validate(value, schema["not"], root, location)
        except ValueError:
            pass
        else:
            raise ValueError(f"JSON Schema not failed at {location}")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"JSON Schema const failed at {location}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"JSON Schema enum failed at {location}")
    types = schema.get("type")
    if types is not None:
        allowed = types if isinstance(types, list) else [types]
        matches = {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "null": value is None,
        }
        if not any(matches.get(str(kind), False) for kind in allowed):
            raise ValueError(f"JSON Schema type failed at {location}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise ValueError(f"JSON Schema minLength failed at {location}")
        if "pattern" in schema and re.fullmatch(str(schema["pattern"]), value) is None:
            raise ValueError(f"JSON Schema pattern failed at {location}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"JSON Schema minimum failed at {location}")
    if isinstance(value, dict):
        required = schema.get("required", [])
        if any(key not in value for key in required):
            raise ValueError(f"JSON Schema required property failed at {location}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and any(key not in properties for key in value):
            raise ValueError(f"JSON Schema additional property failed at {location}")
        for key, child in properties.items():
            if key in value:
                _schema_validate(value[key], child, root, f"{location}.{key}")
    if isinstance(value, list):
        if "items" in schema:
            for index, item in enumerate(value):
                _schema_validate(item, schema["items"], root, f"{location}[{index}]")
        if "contains" in schema:
            count = 0
            for item in value:
                try:
                    _schema_validate(item, schema["contains"], root, location)
                except ValueError:
                    continue
                count += 1
            if count < int(schema.get("minContains", 1)):
                raise ValueError(f"JSON Schema contains failed at {location}")
    for rule in schema.get("allOf", []):
        if "if" not in rule:
            _schema_validate(value, rule, root, location)
            continue
        try:
            _schema_validate(value, rule["if"], root, location)
        except ValueError:
            if "else" in rule:
                _schema_validate(value, rule["else"], root, location)
        else:
            if "then" in rule:
                _schema_validate(value, rule["then"], root, location)


def _schema_path() -> Path:
    from importlib import resources
    return Path(resources.files(__package__) / 'schemas' / 'neutral-ir-1.0.0.schema.json')

def _validate_schema(ir: dict[str, Any]) -> tuple[int, str]:
    schema_path = _schema_path()
    byte_count, digest = _fingerprint(schema_path)
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("checked-in Neutral IR JSON Schema is invalid JSON") from error
    if not isinstance(schema, dict):
        raise ValueError("checked-in Neutral IR JSON Schema is not an object")
    _schema_validate(ir, schema, schema)
    return byte_count, digest


def _full_reader(ir: dict[str, Any]) -> bool:
    return (
        ir["profile"]["detector_status"] == "SUPPORTED"
        and not ir["findings"]
        and not any(pou["findings"] for pou in ir["pous"])
        and all(
            int(counts["partial"]) == 0 and int(counts["unknown"]) == 0
            for counts in ir["coverage"].values()
        )
    )


def _ladder_rows_from_ir(ir: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    for pou in ir["pous"]:
        for record in pou["records"]:
            step = "" if record["step"] is None else str(record["step"])
            kind = record["kind"]
            if kind == "instruction":
                operands = " ".join(
                    str(item["value"])
                    if isinstance(item.get("value"), str)
                    and item["value"] != item["raw_token"]
                    else item["raw_token"]
                    for item in record["operands"]
                )
                rows.append([step, "", record["opcode"] or "", operands, "", "", ""])
            elif kind == "statement":
                rows.append([step, record["text"] or "", "", "", "", "", ""])
            elif kind == "note":
                rows.append([step, "", "", "", "", "", record["text"] or ""])
            elif kind == "continuation":
                operands = " ".join(
                    str(item["value"])
                    if isinstance(item.get("value"), str)
                    and item["value"] != item["raw_token"]
                    else item["raw_token"]
                    for item in record["operands"]
                )
                rows.append(["", "", "", operands, "", "", ""])
            else:
                raise ValueError("opaque record cannot be compared to official export")
    return rows


def _compare_ladder(ir: dict[str, Any], export: Path, expected: dict[str, Any]) -> None:
    actual = read_ladder_tsv(export)
    if (
        set(expected) != {"project", "module", "rows"}
        or not isinstance(expected["project"], str)
        or not isinstance(expected["module"], list)
        or not isinstance(expected["rows"], list)
    ):
        raise ValueError("ladder expectation requires project, module and rows")
    if (
        actual["project"] != expected["project"]
        or actual["module"] != expected["module"]
        or actual["rows"] != expected["rows"]
    ):
        raise ValueError("official Ladder export differs from manifest expectation")
    if _ladder_rows_from_ir(ir) != actual["rows"]:
        raise ValueError("Neutral IR does not exactly match official Ladder export")


def _validate_object_identity(ir: dict[str, Any], expected: object) -> None:
    """Require each acceptance case to name the complete source object set."""
    if not isinstance(expected, dict) or set(expected) != {"project_id", "pous"}:
        raise ValueError("case object identity has an invalid schema")
    if not isinstance(expected["project_id"], str) or not isinstance(expected["pous"], list):
        raise ValueError("case object identity has invalid values")
    actual = {
        "project_id": ir["project"]["project_id"],
        "pous": [
            {
                "pou_id": item["pou_id"],
                "name": item["name"],
                "language": item["language"],
                "program_kind": item["program_kind"],
            }
            for item in ir["pous"]
        ],
    }
    if actual != expected:
        raise ValueError("case project or complete POU identity differs from manifest")


def _validate_lineage(root: Path, value: object, source: Path, exports: dict[str, Path]) -> str:
    """Bind a source and its official exports to one checked corpus manifest."""
    required = {"corpus_id", "manifest", "case_id", "source_name", "export_names", "subject"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("case lineage has an invalid schema")
    if not isinstance(value["corpus_id"], str) or not value["corpus_id"]:
        raise ValueError("case lineage corpus_id is invalid")
    if not isinstance(value["case_id"], str) or not value["case_id"]:
        raise ValueError("case lineage case_id is invalid")
    if value["source_name"] != source.name or not isinstance(value["export_names"], dict):
        raise ValueError("case lineage source or export name differs from manifest")
    manifest = value["manifest"]
    if not isinstance(manifest, dict) or set(manifest) != {"path", "byte_count", "sha256"}:
        raise ValueError("case lineage manifest fingerprint is invalid")
    manifest_path = _within(root, manifest["path"], "case lineage manifest")
    _expect_fingerprint({"byte_count": manifest["byte_count"], "sha256": manifest["sha256"]}, manifest_path, "case lineage manifest")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("case lineage manifest is invalid JSON") from error
    corpus_matches = (
        isinstance(document, dict)
        and (
            document.get("corpus_id") == value["corpus_id"]
            or value["corpus_id"] == f"sha256:{manifest['sha256']}"
        )
    )
    if not corpus_matches:
        raise ValueError("case lineage corpus_id differs from corpus manifest")
    candidates = [item for item in document.get("cases", []) if isinstance(item, dict) and item.get("id") == value["case_id"]]
    subject = value["subject"]
    if candidates:
        if len(candidates) != 1 or candidates[0].get("gx3") != source.name:
            raise ValueError("PROGRAM_FILE_SOURCE_ORPHAN: case lineage source is not recorded by the corpus manifest")
        candidate = candidates[0]
        for kind, artifact in exports.items():
            expected_name = value["export_names"].get(kind)
            recorded_names = {
                candidate.get("rebuild_export"),
                candidate.get("reopen_export"),
                *(
                    item
                    for item in document.get("artifacts", [])
                    if isinstance(item, str)
                ),
            }
            if expected_name != artifact.name or expected_name not in recorded_names:
                raise ValueError("case lineage export is not recorded by the corpus manifest")
    if set(value["export_names"]) != set(exports):
        raise ValueError("case lineage export categories differ from evidence manifest")
    if not isinstance(subject, dict) or set(subject) != {"kind", "program_file_name"}:
        raise ValueError("case lineage subject has an invalid schema")
    if subject["kind"] not in {"ladder", "common_device", "global_label", "local_label", "program_file_device"}:
        raise ValueError("case lineage subject kind is invalid")
    if subject["kind"] == "program_file_device":
        if len(candidates) == 0:
            raise ValueError("PROGRAM_FILE_SOURCE_ORPHAN: program-file corpus case is absent")
        if len(candidates) != 1:
            raise ValueError("PROGRAM_FILE_SOURCE_DUPLICATE: program-file corpus case is not unique")
        scope = document.get("scope")
        if (
            not isinstance(scope, dict)
            or scope.get("comment_kind") != "Each Program Device Comment"
            or scope.get("data_name") != subject["program_file_name"]
            or scope.get("linked_program_name") != subject["program_file_name"]
        ):
            raise ValueError("PROGRAM_DEVICE_SCOPE_MISMATCH: lineage differs from the official UI ground truth")
    elif subject["program_file_name"] is not None:
        raise ValueError("only a program-file device lineage may declare a program-file name")
    return value["corpus_id"]


def _compare_comments(ir: dict[str, Any], export: Path, expected: dict[str, Any]) -> None:
    actual = read_comment_tsv(export)
    required = {"project", "header", "rows", "scope", "decoded_scope", "program_id", "language_slot", "identity_column", "value_column", "source_entry"}
    if set(expected) != required or not isinstance(expected["identity_column"], int) or not isinstance(expected["value_column"], int):
        raise ValueError("comment expectation has an invalid schema")
    identity = expected["identity_column"]
    if identity < 0 or identity >= len(actual["header"]):
        raise ValueError("comment expectation column is outside the official header")
    identities = [row[identity] for row in actual["rows"]]
    if len(set(identities)) != len(identities):
        raise ValueError("official comment export has duplicate identities")
    if (
        actual["project"] != expected["project"]
        or actual["header"] != expected["header"]
        or actual["rows"] != expected["rows"]
    ):
        raise ValueError("official comment export differs from manifest expectation")
    identity, value = expected["identity_column"], expected["value_column"]
    if identity < 0 or value < 0 or identity >= len(actual["header"]) or value >= len(actual["header"]):
        raise ValueError("comment expectation column is outside the official header")
    exported = {(row[identity], row[value]) for row in actual["rows"]}
    if not isinstance(expected["source_entry"], str) or not expected["source_entry"]:
        raise ValueError("comment expectation source_entry is invalid")
    decoded = {
        (item["device_id"], item["value"])
        for item in ir["comments"]
        if item["scope"] == expected["decoded_scope"] and item["program_id"] == expected["program_id"] and item["language_slot"] == expected["language_slot"] and item["provenance"]["source_entry"] == expected["source_entry"]
    }
    if decoded != exported:
        raise ValueError("Neutral IR comments do not exactly match official export")


def _validate_comment_scope(subject: dict[str, Any], expected: dict[str, Any]) -> None:
    if subject["kind"] == "program_file_device":
        required = ("program_device", "common_device", None)
    elif subject["kind"] == "common_device":
        required = ("common_device", "common_device", None)
    else:
        return
    actual = (expected.get("scope"), expected.get("decoded_scope"), expected.get("program_id"))
    if actual != required:
        raise ValueError("comment semantic scope differs from the declared lineage subject")


def _compare_labels(ir: dict[str, Any], export: Path, expected: dict[str, Any]) -> None:
    required = {"project", "header", "rows", "category", "scope", "program_id", "language_slot", "identity_column", "value_column"}
    if set(expected) != required or not isinstance(expected["identity_column"], int) or not isinstance(expected["value_column"], int):
        raise ValueError("label expectation has an invalid schema")
    if expected["category"] not in {"global_label", "local_label"}:
        raise ValueError("label expectation category is unsupported")
    if expected["category"] != expected["scope"]:
        raise ValueError("label expectation category and scope differ")
    actual = read_label_tsv(export, expected["category"])
    identity = expected["identity_column"]
    if identity < 0 or identity >= len(actual["header"]):
        raise ValueError("label expectation column is outside the official header")
    identities = [row[identity] for row in actual["rows"]]
    if len(set(identities)) != len(identities):
        raise ValueError("official label export has duplicate identities")
    if (
        actual["project"] != expected["project"]
        or actual["header"] != expected["header"]
        or actual["rows"] != expected["rows"]
    ):
        raise ValueError("official label export differs from manifest expectation")
    identity, value = expected["identity_column"], expected["value_column"]
    if identity < 0 or value < 0 or identity >= len(actual["header"]) or value >= len(actual["header"]):
        raise ValueError("label expectation column is outside the official header")
    exported = {(row[identity], row[value]) for row in actual["rows"]}
    decoded = {
        (item["label_id"], "" if item["value"] is None else item["value"])
        for item in ir["labels"]
        if item["scope"] == expected["scope"] and item["program_id"] == expected["program_id"] and item["language_slot"] == expected["language_slot"]
    }
    if decoded != exported:
        raise ValueError("Neutral IR labels do not exactly match official export")


def evaluate_evidence_manifest(manifest_path: Path) -> dict[str, Any]:
    """Close Phase 2 only with three independent, exact official-export cases."""
    if manifest_path.is_symlink():
        raise ValueError("evidence manifest must not be a symlink")
    manifest = manifest_path.resolve()
    if not manifest.is_file() or manifest.is_symlink():
        raise ValueError("evidence manifest must be a regular file")
    manifest_before = _fingerprint(manifest)
    schema_before = _fingerprint(_schema_path())
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("evidence manifest is invalid JSON") from error
    if not isinstance(document, dict) or set(document) != {"format", "version", "cases"}:
        raise ValueError("evidence manifest schema is invalid")
    if document["format"] != "plcman.gx3.phase2-evidence-manifest" or document["version"] != "1.0.0":
        raise ValueError("evidence manifest format or version is unsupported")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) < 3:
        raise ValueError("evidence manifest requires at least three cases")
    root = manifest.parent
    source_hashes: set[str] = set()
    case_ids: set[str] = set()
    corpus_ids: set[str] = set()
    evidence_bytes = manifest_before[0] + schema_before[0]
    reports: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {"case_id", "source", "input", "exports", "expected", "identity", "lineage"}:
            raise ValueError(f"manifest case {index} schema is invalid")
        case_id = case["case_id"]
        if not isinstance(case_id, str) or not case_id or case_id in case_ids:
            raise ValueError("evidence manifest has duplicate or invalid case_id")
        case_ids.add(case_id)
        source = _within(root, case["source"], f"case {case_id} source")
        source_count, source_hash = _expect_fingerprint(case["input"], source, f"case {case_id} source")
        evidence_bytes += source_count
        if source_hash in source_hashes:
            raise ValueError("evidence manifest cases must have independent source SHA-256")
        source_hashes.add(source_hash)
        exports, expected = case["exports"], case["expected"]
        allowed_exports = {"ladder", "comments", "labels"}
        if (
            not isinstance(exports, dict)
            or not isinstance(expected, dict)
            or not exports
            or set(exports) != set(expected)
            or not set(exports).issubset(allowed_exports)
        ):
            raise ValueError(f"manifest case {case_id} exports or expectations are invalid")
        artifact_paths: dict[str, Path] = {}
        for kind, artifact in exports.items():
            if not isinstance(artifact, dict) or set(artifact) != {"path", "byte_count", "sha256"}:
                raise ValueError(f"case {case_id} {kind} export fingerprint is invalid")
            artifact_paths[kind] = _within(root, artifact["path"], f"case {case_id} {kind} export")
            artifact_count, _artifact_hash = _expect_fingerprint({"byte_count": artifact["byte_count"], "sha256": artifact["sha256"]}, artifact_paths[kind], f"case {case_id} {kind} export")
            evidence_bytes += artifact_count
        corpus_id = _validate_lineage(root, case["lineage"], source, artifact_paths)
        if corpus_id in corpus_ids:
            raise ValueError("evidence manifest cases must have independent corpus lineage")
        corpus_ids.add(corpus_id)
        lineage_manifest = case["lineage"]["manifest"]
        evidence_bytes += int(lineage_manifest["byte_count"])
        if evidence_bytes > _MAX_EVIDENCE_BYTES:
            raise ValueError("evidence manifest cumulative byte budget exceeded")
        first = build_neutral_ir(source)
        second = build_neutral_ir(source)
        if _canonical(first) != _canonical(second):
            raise ValueError("canonical IR is not byte-identical")
        if first["input"]["byte_count"] != source_count or first["input"]["sha256"] != source_hash:
            raise ValueError("Neutral IR input fingerprint differs from manifest")
        if second["input"]["byte_count"] != source_count or second["input"]["sha256"] != source_hash:
            raise ValueError("second Neutral IR input fingerprint differs from manifest")
        validate_ir(first)
        _validate_object_identity(first, case["identity"])
        if _validate_schema(first) != schema_before:
            raise ValueError("Neutral IR JSON Schema changed during validation")
        reader_full = _full_reader(first)
        if reader_full:
            if "ladder" in artifact_paths:
                _compare_ladder(first, artifact_paths["ladder"], expected["ladder"])
            if "comments" in artifact_paths:
                _validate_comment_scope(case["lineage"]["subject"], expected["comments"])
                _compare_comments(first, artifact_paths["comments"], expected["comments"])
            if "labels" in artifact_paths:
                _compare_labels(first, artifact_paths["labels"], expected["labels"])
        if _fingerprint(source) != (source_count, source_hash):
            raise ValueError("source SHA-256 or byte count changed during manifest acceptance")
        for kind, artifact in exports.items():
            _expect_fingerprint(
                {"byte_count": artifact["byte_count"], "sha256": artifact["sha256"]},
                artifact_paths[kind],
                f"case {case_id} {kind} export",
            )
        reports.append({
            "case_id": case_id,
            "input": {"byte_count": source_count, "sha256": source_hash, "unchanged": True},
            "reader_coverage_decision": "FULL" if reader_full else "BLOCKED",
            "schema_validated": True,
            "official_export_compared": reader_full,
            "cpu": first["profile"]["cpu_ui_selection"],
            "language": first["profile"]["language"],
            "profile": first["profile"]["profile_id"],
            "compared_export_types": sorted(artifact_paths),
            "scope_findings": (
                [{
                    "code": "PROGRAM_DEVICE_SCOPE_UNVERIFIED",
                    "status": "PARTIAL",
                    "severity": "PARTIAL",
                    "blocking": False,
                    "program_file_name": case["lineage"]["subject"]["program_file_name"],
                    "detail": "official UI ground truth links the comment data to the program file; archive POU and device-comment storage relation is not decoded",
                }]
                if case["lineage"]["subject"]["kind"] == "program_file_device"
                else []
            ),
        })
    covered_categories = {
        category
        for case in cases
        for category in case["exports"]
    }
    if covered_categories != {"ladder", "comments", "labels"}:
        raise ValueError("evidence manifest does not cover all official export categories")
    if _fingerprint(manifest) != manifest_before:
        raise ValueError("evidence manifest changed during acceptance")
    if _fingerprint(_schema_path()) != schema_before:
        raise ValueError("Neutral IR JSON Schema changed during acceptance")
    schema_count, schema_hash = schema_before
    full_reader = all(item["reader_coverage_decision"] == "FULL" for item in reports)
    official_export_compared = all(item["official_export_compared"] for item in reports)
    full = full_reader and official_export_compared
    authorities = {
        (item["cpu"], item["language"], item["profile"])
        for item in reports
    }
    if len(authorities) != 1:
        raise ValueError("evidence manifest cases do not share one authoritative profile")
    cpu, language, profile = next(iter(authorities))
    blockers: list[dict[str, Any]] = []
    if not full_reader:
        blockers.append({"code": "READER_COVERAGE_NOT_FULL", "count": sum(item["reader_coverage_decision"] != "FULL" for item in reports)})
    if not official_export_compared:
        blockers.append({"code": "OFFICIAL_EXPORT_COMPARISON_INCOMPLETE", "count": sum(not item["official_export_compared"] for item in reports)})
    return {
        "format": "plcman.gx3.phase2-acceptance",
        "version": "1.0.0",
        "evaluator_provenance": {
            "evaluator": "gx3_fx5_parser_toolkit.acceptance.evaluate_evidence_manifest",
            "evidence_manifest_path": str(manifest),
            "evidence_manifest_byte_count": manifest_before[0],
            "evidence_manifest_sha256": manifest_before[1],
        },
        "decision": "FULL" if full else "BLOCKED",
        "phase2_closed": full,
        "independent_gx3_set_verified": True,
        "json_schema_validated": True,
        "official_export_compared": official_export_compared,
        "scope_findings": [
            finding
            for item in reports
            for finding in item["scope_findings"]
        ],
        "cpu": cpu,
        "language": language,
        "profile": profile,
        "schema": {"byte_count": schema_count, "sha256": schema_hash},
        "cases": reports,
        "readiness_blockers": blockers,
    }
