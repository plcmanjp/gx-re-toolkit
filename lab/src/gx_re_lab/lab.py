"""research-only GX3 source/export comparator.

Input schema: strict JSON case manifest, GX3 source, UTF-16LE GX Works3 Ladder CSV.
Output schema: one path-free JSON report on stdout.  Dependencies: FX5 parser and
local retained input snapshot.  Command: python lab.py verify --manifest ...
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import re
from pathlib import Path
from typing import Any

from gx3_fx5_parser_toolkit.ir import build_neutral_ir
from . import snapshot as snapshot_module
from .snapshot import InputSnapshot, _handle_final_path, _open_input_snapshot, _reject_link_like_ancestors, _stat_identity

MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_EXPORT_BYTES = 8 * 1024 * 1024
HEADER = ["Step No.", "Line Statement", "Instruction", "I/O (Device)", "Blank", "P/I Statement", "Note"]
TOP_KEYS = {"format", "version", "case_id", "profile", "source", "official_export", "expected"}
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
POU_ID = re.compile(r"[0-9]{1,32}\Z")
KNOWN_PROFILE = ("FX5U", "Ladder", "mitsubishi.gx3.fx5u.ladder")


class LabError(ValueError):
    """A fail-closed input or comparison error with a stable public code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _regular(path: Path, label: str, cap: int) -> Path:
    try:
        checked = _reject_link_like_ancestors(path, label)
    except Exception as error:
        raise LabError("LINK_LIKE_INPUT") from error
    if not checked.is_file() or checked.is_symlink() or checked.stat().st_size > cap:
        raise LabError("INPUT_CAP_OR_TYPE")
    return checked


def _retained_bytes(path: Path, label: str, cap: int) -> tuple[bytes, str]:
    """Retain one no-follow handle and read no more than cap plus one byte."""
    checked = _regular(path, label, cap)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(checked, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > cap:
            raise LabError("INPUT_CAP_OR_TYPE")
        identity = _stat_identity(opened)
        final_path = _handle_final_path(descriptor)
        intended = os.path.normcase(os.path.abspath(checked.resolve()))
        if final_path != intended:
            raise LabError("LINK_LIKE_INPUT")
        chunks: list[bytes] = []
        total = 0
        while total < cap + 1:
            block = os.read(descriptor, min(1024 * 1024, cap + 1 - total))
            if not block:
                break
            total += len(block)
            chunks.append(block)
        if total > cap:
            raise LabError("INPUT_CAP_OR_TYPE")
        body = b"".join(chunks)
        snapshot = InputSnapshot(descriptor, checked, body, _sha256_bytes(body), identity, final_path)
        snapshot.verify()
        return snapshot.body, snapshot.sha256
    finally:
        os.close(descriptor)


def _json_no_duplicates(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise LabError("MANIFEST_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(LabError("MANIFEST_NONFINITE")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabError("MANIFEST_INVALID_JSON") from error
    if not isinstance(value, dict):
        raise LabError("MANIFEST_SCHEMA")
    return value


def _expect_keys(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LabError("MANIFEST_SCHEMA")
    return value


def _fingerprint(value: object) -> tuple[int, str]:
    row = _expect_keys(value, {"byte_count", "sha256"})
    if not isinstance(row["byte_count"], int) or isinstance(row["byte_count"], bool) or row["byte_count"] < 0:
        raise LabError("MANIFEST_SCHEMA")
    if not isinstance(row["sha256"], str) or len(row["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in row["sha256"]):
        raise LabError("MANIFEST_SCHEMA")
    return row["byte_count"], row["sha256"]


def _validate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    if (set(value) != TOP_KEYS or value.get("format") != "plcman.gx-re-lab.case-manifest" or
            type(value.get("version")) is not int or value["version"] != 1):
        raise LabError("MANIFEST_SCHEMA")
    if not isinstance(value["case_id"], str) or not CASE_ID.fullmatch(value["case_id"]):
        raise LabError("MANIFEST_SCHEMA")
    profile = _expect_keys(value["profile"], {"cpu", "language", "profile_id"})
    if tuple(profile[key] for key in ("cpu", "language", "profile_id")) != KNOWN_PROFILE:
        raise LabError("MANIFEST_SCHEMA")
    _fingerprint(value["source"])
    export = _expect_keys(value["official_export"], {"byte_count", "sha256", "project_title", "module"})
    _fingerprint({"byte_count": export["byte_count"], "sha256": export["sha256"]})
    if not isinstance(export["project_title"], str) or not isinstance(export["module"], list) or len(export["module"]) != 2 or not all(isinstance(item, str) for item in export["module"]):
        raise LabError("MANIFEST_SCHEMA")
    expected = _expect_keys(value["expected"], {"pous", "selected_pou_id", "rows"})
    if (not isinstance(expected["selected_pou_id"], str) or not POU_ID.fullmatch(expected["selected_pou_id"]) or
            not isinstance(expected["pous"], list) or not expected["pous"]):
        raise LabError("MANIFEST_SCHEMA")
    ids: set[str] = set()
    for pou in expected["pous"]:
        row = _expect_keys(pou, {"pou_id", "name", "language", "program_kind", "execution_order", "relations"})
        if (not isinstance(row["pou_id"], str) or not POU_ID.fullmatch(row["pou_id"]) or row["pou_id"] in ids or
                not all(isinstance(row[key], str) for key in ("name", "language", "program_kind")) or
                not isinstance(row["execution_order"], int) or isinstance(row["execution_order"], bool) or
                not isinstance(row["relations"], list) or not all(isinstance(item, str) for item in row["relations"])):
            raise LabError("MANIFEST_SCHEMA")
        ids.add(row["pou_id"])
    if expected["selected_pou_id"] not in ids or not isinstance(expected["rows"], list):
        raise LabError("MANIFEST_SCHEMA")
    for row in expected["rows"]:
        if not isinstance(row, list) or len(row) != 7 or not all(isinstance(item, str) for item in row):
            raise LabError("MANIFEST_SCHEMA")
    return value


def _read_manifest(path: Path, pinned_hash: str) -> dict[str, Any]:
    raw, actual_hash = _retained_bytes(path, "--manifest", MAX_MANIFEST_BYTES)
    if actual_hash != pinned_hash.casefold():
        raise LabError("MANIFEST_PIN_MISMATCH")
    return _validate_manifest(_json_no_duplicates(raw))


def _read_export(path: Path) -> dict[str, Any]:
    raw, actual_hash = _retained_bytes(path, "--official-export", MAX_EXPORT_BYTES)
    if not raw.startswith(b"\xff\xfe") or b"\r\x00\n\x00" not in raw:
        raise LabError("OFFICIAL_EXPORT_FORMAT")
    try:
        text = raw[2:].decode("utf-16le")
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter="\t", quotechar='"', strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise LabError("OFFICIAL_EXPORT_FORMAT") from error
    replay = io.StringIO(newline="")
    csv.writer(replay, delimiter="\t", quotechar='"', quoting=csv.QUOTE_ALL, lineterminator="\r\n").writerows(rows)
    if raw != b"\xff\xfe" + replay.getvalue().encode("utf-16le"):
        raise LabError("OFFICIAL_EXPORT_FORMAT")
    if len(rows) < 3 or len(rows[0]) != 1 or len(rows[1]) != 2 or rows[2] != HEADER or any(len(row) != 7 for row in rows[3:]):
        raise LabError("OFFICIAL_EXPORT_FORMAT")
    return {"byte_count": len(raw), "sha256": actual_hash, "project_title": rows[0][0], "module": rows[1], "rows": rows[3:]}


def _surface(records: list[dict[str, Any]]) -> list[list[str]]:
    """Independent seven-column projection.  It intentionally does not use FX5 CSV code."""
    result: list[list[str]] = []
    for record in records:
        kind, step = record.get("kind"), record.get("step")
        step_value = "" if step is None else str(step)
        operands = " ".join(str(item.get("value")) if isinstance(item.get("value"), str) and item.get("value") != item.get("raw_token") else str(item.get("raw_token", "")) for item in record.get("operands", []))
        if kind == "instruction":
            result.append([step_value, "", str(record.get("opcode") or ""), operands, "", "", ""])
        elif kind == "statement":
            result.append([step_value, str(record.get("text") or ""), "", "", "", "", ""])
        elif kind == "note":
            result.append([step_value, "", "", "", "", "", str(record.get("text") or "")])
        elif kind == "continuation":
            result.append(["", "", "", operands, "", "", ""])
        else:
            raise LabError("IR_UNSUPPORTED_RECORD")
    return result


def _parse_snapshot(source: Path) -> dict[str, Any]:
    checked = _regular(source, "--source", 256 * 1024 * 1024)
    snapshot = _open_input_snapshot(checked)
    temp_name: str | None = None
    try:
        descriptor, temp_name = tempfile.mkstemp(suffix=".gx3")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(snapshot.body)
        copied = Path(temp_name)
        if copied.read_bytes() != snapshot.body:
            raise LabError("SNAPSHOT_COPY_CHANGED")
        ir = build_neutral_ir(copied)
        if copied.read_bytes() != snapshot.body:
            raise LabError("SNAPSHOT_COPY_CHANGED")
        snapshot.verify()
        if ir["input"]["sha256"] != snapshot.sha256 or ir["input"]["byte_count"] != len(snapshot.body):
            raise LabError("SOURCE_SNAPSHOT_MISMATCH")
        return ir
    finally:
        snapshot.close()
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def _assert_ir_complete(ir: dict[str, Any]) -> None:
    profile = ir.get("profile")
    if not isinstance(profile, dict) or profile.get("detector_status") != "SUPPORTED":
        raise LabError("IR_INCOMPLETE")
    if ir.get("findings") != [] or not isinstance(ir.get("pous"), list) or not ir["pous"]:
        raise LabError("IR_INCOMPLETE")
    for pou in ir["pous"]:
        if not isinstance(pou, dict) or pou.get("findings") != []:
            raise LabError("IR_INCOMPLETE")
    coverage = ir.get("coverage")
    if not isinstance(coverage, dict) or not coverage:
        raise LabError("IR_INCOMPLETE")
    for counts in coverage.values():
        if not isinstance(counts, dict) or set(counts) != {"total", "decoded", "partial", "unknown"}:
            raise LabError("IR_INCOMPLETE")
        if any(type(counts[key]) is not int or counts[key] < 0 for key in counts):
            raise LabError("IR_INCOMPLETE")
        if counts["partial"] or counts["unknown"] or counts["total"] != counts["decoded"]:
            raise LabError("IR_INCOMPLETE")


def _parser_artifact_sha256() -> str:
    """Bind identity to the installed parser distribution's Python source closure."""
    from importlib.metadata import distribution
    installed = distribution("gx3-fx5-parser-toolkit")
    paths = sorted((item for item in installed.files or ()
                    if item.suffix == ".py" and item.parts[0] in
                    {"gx3_core", "gx3_fx5_profile", "gx3_fx5_parser_toolkit"}), key=str)
    if not paths:
        raise LabError("IR_PROVENANCE_INVALID")
    digest = hashlib.sha256()
    for item in paths:
        relative = item.as_posix().encode("ascii")
        body = Path(installed.locate_file(item)).read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return digest.hexdigest()


def verify(manifest_path: Path, manifest_sha256: str, source_path: Path, export_path: Path) -> dict[str, Any]:
    if len(manifest_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in manifest_sha256):
        raise LabError("MANIFEST_PIN_INVALID")
    manifest = _read_manifest(manifest_path, manifest_sha256)
    source_count, source_hash = _fingerprint(manifest["source"])
    export = _read_export(export_path)
    export_pin = _fingerprint({"byte_count": manifest["official_export"]["byte_count"], "sha256": manifest["official_export"]["sha256"]})
    if (export["byte_count"], export["sha256"]) != export_pin:
        raise LabError("OFFICIAL_EXPORT_FINGERPRINT_MISMATCH")
    if export["project_title"] != manifest["official_export"]["project_title"] or export["module"] != manifest["official_export"]["module"]:
        raise LabError("OFFICIAL_EXPORT_TITLE_MISMATCH")
    ir = _parse_snapshot(source_path)
    if (ir["input"]["byte_count"], ir["input"]["sha256"]) != (source_count, source_hash):
        raise LabError("SOURCE_FINGERPRINT_MISMATCH")
    profile = manifest["profile"]
    actual_profile = ir["profile"]
    if (actual_profile["cpu_ui_selection"], actual_profile["language"], actual_profile["profile_id"]) != KNOWN_PROFILE:
        raise LabError("PROFILE_MISMATCH")
    _assert_ir_complete(ir)
    actual_pous = [{key: pou[key] for key in ("pou_id", "name", "language", "program_kind", "execution_order", "relations")} for pou in ir["pous"]]
    if actual_pous != manifest["expected"]["pous"]:
        raise LabError("POU_IDENTITY_OR_RELATION_MISMATCH")
    selected = next(pou for pou in ir["pous"] if pou["pou_id"] == manifest["expected"]["selected_pou_id"])
    surface = _surface(selected["records"])
    if surface != manifest["expected"]["rows"] or export["rows"] != manifest["expected"]["rows"] or surface != export["rows"]:
        raise LabError("LADDER_SURFACE_MISMATCH")
    producer = ir.get("producer")
    if (not isinstance(producer, dict) or not all(isinstance(producer.get(key), str) and len(producer[key]) <= 128 for key in ("package", "version", "source_commit"))):
        raise LabError("IR_PROVENANCE_INVALID")
    manifest_raw, manifest_hash = _retained_bytes(manifest_path, "--manifest", MAX_MANIFEST_BYTES)
    if manifest_hash != manifest_sha256.casefold():
        raise LabError("MANIFEST_PIN_MISMATCH")
    return {
        "case_id": manifest["case_id"], "decision": "SOURCE_MATCH", "lifecycle": "NOT_RUN",
        "selected_pou_id": manifest["expected"]["selected_pou_id"],
        "execution": {
            "manifest": {"byte_count": len(manifest_raw), "sha256": manifest_hash},
            "source": {"byte_count": ir["input"]["byte_count"], "sha256": ir["input"]["sha256"]},
            "official_export": {"byte_count": export["byte_count"], "sha256": export["sha256"]},
            "parser": {**{key: producer[key] for key in ("package", "version", "source_commit")}, "artifact_sha256": _parser_artifact_sha256()},
            "snapshot_provider": {"module": "gx_re_lab.snapshot", "core_sha256": _sha256_bytes(Path(snapshot_module.__file__).read_bytes())},
            "lab_sha256": _sha256_bytes(Path(__file__).read_bytes()),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="research-only GX3 source/export comparator")
    command = parser.add_subparsers(dest="command", required=True)
    verify_parser = command.add_parser("verify")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--manifest-sha256", required=True)
    verify_parser.add_argument("--source", required=True)
    verify_parser.add_argument("--official-export", required=True)
    args = parser.parse_args(argv)
    try:
        report = verify(Path(args.manifest), args.manifest_sha256, Path(args.source), Path(args.official_export))
    except LabError as error:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": [error.code]}
    except Exception:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": ["PARSER_BLOCKED"]}
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["decision"] == "SOURCE_MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
