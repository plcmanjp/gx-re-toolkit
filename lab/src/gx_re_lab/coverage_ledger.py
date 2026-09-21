"""FR01/08 profile-scoped research coverage ledger.

Input schema: one UTF-8 JSON evidence document whose SHA-256 is supplied on
the command line. Output schema: a new versioned JSON ledger. Dependencies:
Python standard library only. Command: ``python coverage_ledger.py --evidence
<evidence.json> --evidence-sha256 <pin> --source <pinned-source> --artifact-root
<local-evidence-root> --output <new-ledger.json>``.

Each evidence document represents exactly one profile. Layer accounting uses
the mutually exclusive ``observed_only``, ``decoded``, ``partial``,
``unknown``, and ``unmeasured`` categories for one stated denominator, or is entirely null with a required
reason when its atomic denominator is not measured. The ledger is research
evidence only: it does not combine profiles, calculate a rate, or make a
support or lifecycle claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

MAX_EVIDENCE_BYTES = 1 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 32
FORMAT = "plcman.gx-re-lab.coverage-evidence"
LEDGER_FORMAT = "plcman.gx-re-lab.coverage-ledger"
HEX = set("0123456789abcdef")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class LedgerError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fail(condition: bool, code: str = "EVIDENCE_SCHEMA") -> None:
    if not condition:
        raise LedgerError(code)


def _read_pinned(path: Path, pin: str) -> tuple[bytes, str]:
    _fail(isinstance(pin, str) and len(pin) == 64 and set(pin.casefold()) <= HEX, "EVIDENCE_PIN_SCHEMA")
    path = _regular_no_link(path, "EVIDENCE")
    total, chunks = 0, []
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            _fail(total <= MAX_EVIDENCE_BYTES, "EVIDENCE_CAP")
            chunks.append(block)
    body = b"".join(chunks)
    digest = hashlib.sha256(body).hexdigest()
    _fail(digest == pin.casefold(), "EVIDENCE_PIN_MISMATCH")
    return body, digest


def _json_no_duplicates(body: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise LedgerError("EVIDENCE_DUPLICATE_KEY")
            result[key] = value
        return result
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _value: (_ for _ in ()).throw(LedgerError("EVIDENCE_NONFINITE")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise LedgerError("EVIDENCE_JSON") from error
    _fail(isinstance(value, dict))
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        _fail(depth <= MAX_JSON_DEPTH, "EVIDENCE_DEPTH")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _identifier(value: object) -> str:
    _fail(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None)
    return value


def _sha256(value: object) -> str:
    _fail(isinstance(value, str) and len(value) == 64 and set(value) <= HEX)
    return value


def _profile(value: object) -> dict[str, str]:
    _fail(isinstance(value, dict) and set(value) == {"profile_id", "cpu", "language"})
    for field in ("profile_id", "cpu", "language"):
        _fail(isinstance(value[field], str) and 0 < len(value[field]) <= 128)
    return value


def _source(value: object) -> dict[str, Any]:
    _fail(isinstance(value, dict) and set(value) == {"byte_count", "sha256"})
    _fail(type(value["byte_count"]) is int and value["byte_count"] >= 0)
    _sha256(value["sha256"])
    return value


def _accounting(value: object, null_reason: object) -> dict[str, int | None]:
    keys = {"denominator", "observed_only", "decoded", "partial", "unknown", "unmeasured"}
    _fail(isinstance(value, dict) and set(value) == keys)
    values = tuple(value[key] for key in ("denominator", "observed_only", "decoded", "partial", "unknown", "unmeasured"))
    if value["denominator"] is None:
        _fail(all(item is None for item in values) and isinstance(null_reason, str) and 0 < len(null_reason) <= 512, "NULL_DENOMINATOR_REASON")
    else:
        _fail(null_reason is None)
        _fail(all(type(item) is int and item >= 0 for item in values))
        _fail(sum(value[key] for key in ("observed_only", "decoded", "partial", "unknown", "unmeasured")) == value["denominator"], "ACCOUNTING_CONSERVATION")
    return value


def _relative_path(value: object) -> str:
    _fail(isinstance(value, str) and value and "\\" not in value)
    posix, windows = PurePosixPath(value), PureWindowsPath(value)
    _fail(not posix.is_absolute() and not windows.is_absolute() and not windows.drive and not windows.root)
    _fail(all(part not in {"", ".", ".."} for part in posix.parts))
    return value


def _evidence_refs(value: object) -> list[dict[str, Any]]:
    _fail(isinstance(value, list) and 1 <= len(value) <= 32)
    result = []
    for item in value:
        _fail(isinstance(item, dict) and set(item) == {"kind", "relative_path", "byte_count", "sha256"})
        _fail(type(item["byte_count"]) is int and 0 <= item["byte_count"] <= MAX_ARTIFACT_BYTES)
        result.append({"kind": _identifier(item["kind"]), "relative_path": _relative_path(item["relative_path"]), "byte_count": item["byte_count"], "sha256": _sha256(item["sha256"])})
    _fail(len({item["relative_path"] for item in result}) == len(result))
    return result


def _layer(value: object) -> dict[str, Any]:
    keys = {"layer_id", "denominator_kind", "accounting", "null_reason", "evidence"}
    _fail(isinstance(value, dict) and set(value) == keys)
    return {"layer_id": _identifier(value["layer_id"]), "denominator_kind": _identifier(value["denominator_kind"]), "accounting": _accounting(value["accounting"], value["null_reason"]), "null_reason": value["null_reason"], "evidence": _evidence_refs(value["evidence"])}


def read_evidence(path: Path, pin: str) -> tuple[dict[str, Any], str]:
    body, digest = _read_pinned(path, pin)
    value = _json_no_duplicates(body)
    keys = {"format", "version", "evidence_id", "profile", "source", "layers"}
    _fail(set(value) == keys and value.get("format") == FORMAT and type(value.get("version")) is int and value["version"] == 1)
    _identifier(value["evidence_id"]); _profile(value["profile"]); _source(value["source"])
    _fail(isinstance(value["layers"], list) and 1 <= len(value["layers"]) <= 128)
    layers = [_layer(item) for item in value["layers"]]
    _fail(len({item["layer_id"] for item in layers}) == len(layers))
    value["layers"] = layers
    return value, digest


def _is_link_like(path: Path) -> bool:
    junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction) and bool(junction()))


def _regular_no_link(path: Path, label: str, root: Path | None = None) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise LedgerError(label + "_MISSING") from error
    if root is not None:
        try:
            resolved.relative_to(root.resolve(strict=True))
        except (ValueError, OSError) as error:
            raise LedgerError(label + "_OUTSIDE_ROOT") from error
    chain = [path, *path.parents]
    if root is not None:
        try:
            limit = chain.index(root)
        except ValueError:
            raise LedgerError(label + "_OUTSIDE_ROOT")
        chain = chain[:limit + 1]
    if any(_is_link_like(item) for item in chain) or not resolved.is_file():
        raise LedgerError(label + "_TYPE")
    return resolved


def _fingerprint_file(path: Path, cap: int, label: str) -> dict[str, Any]:
    checked = _regular_no_link(path, label)
    digest, total = hashlib.sha256(), 0
    with checked.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            _fail(total <= cap, label + "_CAP")
            digest.update(block)
    return {"byte_count": total, "sha256": digest.hexdigest()}


def verify_bound_files(evidence: dict[str, Any], source_path: Path, artifact_root: Path) -> None:
    source = _fingerprint_file(source_path, MAX_SOURCE_BYTES, "SOURCE")
    _fail(source == evidence["source"], "SOURCE_FINGERPRINT_MISMATCH")
    _regular_no_link(artifact_root, "ARTIFACT_ROOT") if artifact_root.is_file() else None
    _fail(artifact_root.is_dir() and not _is_link_like(artifact_root), "ARTIFACT_ROOT_TYPE")
    root = artifact_root.resolve(strict=True)
    total = 0
    for reference in evidence["layers"]:
        for item in reference["evidence"]:
            path = artifact_root.joinpath(*PurePosixPath(item["relative_path"]).parts)
            checked = _regular_no_link(path, "ARTIFACT", artifact_root)
            fingerprint = _fingerprint_file(checked, MAX_ARTIFACT_BYTES, "ARTIFACT")
            total += fingerprint["byte_count"]
            _fail(total <= MAX_ARTIFACT_TOTAL_BYTES, "ARTIFACT_TOTAL_CAP")
            _fail(fingerprint == {"byte_count": item["byte_count"], "sha256": item["sha256"]}, "ARTIFACT_FINGERPRINT_MISMATCH")


def build_ledger(evidence: dict[str, Any], evidence_sha256: str, source_path: Path, artifact_root: Path) -> dict[str, Any]:
    verify_bound_files(evidence, source_path, artifact_root)
    return {"format": LEDGER_FORMAT, "version": 1, "decision": "RESEARCH_LEDGER", "lifecycle": "NOT_RUN", "aggregation": "FORBIDDEN_SINGLE_PROFILE_ONLY", "support_claim": "NOT_MADE", "input_evidence": {"evidence_id": evidence["evidence_id"], "sha256": evidence_sha256}, "profile": evidence["profile"], "source": evidence["source"], "layers": evidence["layers"]}


def _publish_new(path: Path, payload: bytes) -> None:
    _fail(path.parent.is_dir() and not path.is_symlink(), "OUTPUT_PARENT")
    _fail(not path.exists() and not path.is_symlink(), "OUTPUT_EXISTS")
    _fail(len(payload) <= MAX_OUTPUT_BYTES, "OUTPUT_CAP")
    try:
        with path.open("xb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    except FileExistsError as error:
        raise LedgerError("OUTPUT_EXISTS") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--evidence-sha256", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        evidence, digest = read_evidence(args.evidence, args.evidence_sha256)
        ledger = build_ledger(evidence, digest, args.source, args.artifact_root)
        payload = (json.dumps(ledger, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        verify_bound_files(evidence, args.source, args.artifact_root)
        _publish_new(args.output, payload)
    except (LedgerError, OSError) as error:
        print(json.dumps({"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blocker": error.code if isinstance(error, LedgerError) else "LEDGER_IO"}, sort_keys=True))
        return 1
    print(json.dumps({"decision": "RESEARCH_LEDGER", "lifecycle": "NOT_RUN", "profile_id": evidence["profile"]["profile_id"], "layer_count": len(evidence["layers"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
