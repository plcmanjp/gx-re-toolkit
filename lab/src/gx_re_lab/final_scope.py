"""final profile-scope evidence projection.

Input schema: a pinned UTF-8 manifest that lists profile-local projection
artifacts below ``--artifact-root``. Output schema: a new JSON document with
one referenced scope per input profile. Dependencies: Python standard library
and the local ``coverage_ledger`` safety helpers. Command:
``python final_scope.py --manifest <manifest.json> --manifest-sha256 <pin>
--artifact-root <root> --output <new-report.json>``.

This is a read-only projection over prior evidence. It neither reruns GX nor
calculates totals, rates, support, Q acceptance, or an Issue conclusion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from . import coverage_ledger as safe

FORMAT = "plcman.issue32.final-scope-manifest"
REPORT_FORMAT = "plcman.issue32.final-scope-report"
MAX_PROFILES = 8
P002_KIND = "p002_fr08_profile_conformance"
R04_KIND = "r04_fr08_current_1128"
Q_STATUSES = {"BLOCKED", "NOT_RUN", "NOT_REPORTED"}
R04_PROFILE = {"profile_id": "mitsubishi.gx3.r04.ladder", "cpu": "R04CPU", "language": "Ladder"}
P002_DECISION = "P002_FX5U_FR08_PROFILE_CONFORMANCE_SATISFIED_SCOPE_BOUND"
R04_DECISION = "CURRENT_1_128_R04_ACCEPTED24_CREATED_LINEAGE_SCOPE_BOUND"


class FinalScopeError(safe.LedgerError):
    pass


def _fail(condition: bool, code: str = "FINAL_SCOPE_SCHEMA") -> None:
    if not condition:
        raise FinalScopeError(code)


def _mapping(value: object, code: str) -> dict[str, Any]:
    _fail(isinstance(value, dict), code)
    return value


def _required(value: dict[str, Any], key: str, code: str) -> Any:
    _fail(key in value, code)
    return value[key]


def _profile(value: object) -> dict[str, str]:
    profile = _mapping(value, "PROFILE_SCHEMA")
    _fail(set(profile) == {"profile_id", "cpu", "language"}, "PROFILE_SCHEMA")
    for field in profile:
        _fail(isinstance(profile[field], str) and 0 < len(profile[field]) <= 128, "PROFILE_SCHEMA")
    return profile


def _reference(value: object) -> dict[str, Any]:
    reference = _mapping(value, "PROJECTION_REFERENCE_SCHEMA")
    _fail(set(reference) == {"relative_path", "byte_count", "sha256"}, "PROJECTION_REFERENCE_SCHEMA")
    relative_path = safe._relative_path(reference["relative_path"])
    _fail(type(reference["byte_count"]) is int and 0 <= reference["byte_count"] <= safe.MAX_ARTIFACT_BYTES,
          "PROJECTION_REFERENCE_SCHEMA")
    return {"relative_path": relative_path, "byte_count": reference["byte_count"], "sha256": safe._sha256(reference["sha256"])}


def _q_scope(value: object) -> dict[str, str]:
    if value is None:
        return {"status": "NOT_REPORTED"}
    q_scope = _mapping(value, "Q_SCOPE_SCHEMA")
    _fail(set(q_scope) == {"status"} and q_scope["status"] in Q_STATUSES, "Q_SCOPE_SCHEMA")
    return {"status": q_scope["status"]}


def _entry(value: object) -> dict[str, Any]:
    entry = _mapping(value, "PROFILE_ENTRY_SCHEMA")
    _fail(set(entry) in ({"profile", "kind", "projection"}, {"profile", "kind", "projection", "q_scope"}),
          "PROFILE_ENTRY_SCHEMA")
    _fail(entry["kind"] in {P002_KIND, R04_KIND}, "PROFILE_KIND")
    return {"profile": _profile(entry["profile"]), "kind": entry["kind"],
            "projection": _reference(entry["projection"]), "q_scope": _q_scope(entry.get("q_scope"))}


def read_manifest(path: Path, pin: str) -> tuple[dict[str, Any], str]:
    body, digest = safe._read_pinned(path, pin)
    manifest = safe._json_no_duplicates(body)
    _fail(set(manifest) == {"format", "version", "scope_id", "profiles"}, "MANIFEST_SCHEMA")
    _fail(manifest["format"] == FORMAT and manifest["version"] == 1, "MANIFEST_SCHEMA")
    safe._identifier(manifest["scope_id"])
    _fail(isinstance(manifest["profiles"], list) and 1 <= len(manifest["profiles"]) <= MAX_PROFILES,
          "PROFILE_SET_SCHEMA")
    profiles = [_entry(item) for item in manifest["profiles"]]
    _fail(len({item["profile"]["profile_id"] for item in profiles}) == len(profiles), "DUPLICATE_PROFILE")
    manifest["profiles"] = profiles
    return manifest, digest


def _projection_snapshot(root: Path, reference: dict[str, Any]) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    _fail(root.is_dir() and not safe._is_link_like(root), "ARTIFACT_ROOT_TYPE")
    path = root.joinpath(*PurePosixPath(reference["relative_path"]).parts)
    checked = safe._regular_no_link(path, "PROJECTION", root)
    digest, total, chunks = hashlib.sha256(), 0, []
    with checked.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            _fail(total <= safe.MAX_ARTIFACT_BYTES, "PROJECTION_CAP")
            digest.update(block)
            chunks.append(block)
    body = b"".join(chunks)
    fingerprint = {"byte_count": total, "sha256": digest.hexdigest()}
    _fail(fingerprint == {"byte_count": reference["byte_count"], "sha256": reference["sha256"]},
          "PROJECTION_FINGERPRINT_MISMATCH")
    return checked, fingerprint, safe._json_no_duplicates(body)


def _p002_scope(entry: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    _fail(evidence.get("format") == "plcman.issue32.p002-fr08-profile-conformance-projection" and
          evidence.get("version") == 1, "P002_PROJECTION_SCHEMA")
    source_profile = _mapping(_required(evidence, "profile", "P002_PROJECTION_SCHEMA"), "P002_PROFILE_SCHEMA")
    _fail(source_profile.get("id") == entry["profile"]["profile_id"] and
          source_profile.get("cpu") == entry["profile"]["cpu"] and
          source_profile.get("language") == entry["profile"]["language"], "P002_PROFILE_MISMATCH")
    layers = _mapping(_required(evidence, "layer_statuses", "P002_PROJECTION_SCHEMA"), "P002_LAYERS_SCHEMA")
    boundary = _mapping(_required(evidence, "authority_boundary", "P002_PROJECTION_SCHEMA"), "P002_BOUNDARY_SCHEMA")
    fresh = _mapping(_required(evidence, "fresh_deterministic_execution", "P002_PROJECTION_SCHEMA"), "P002_FRESH_SCHEMA")
    _fail(_required(evidence, "decision", "P002_PROJECTION_SCHEMA") == P002_DECISION and
          isinstance(_required(fresh, "status", "P002_FRESH_SCHEMA"), str), "P002_PROJECTION_SCHEMA")
    return {"reference_decision": evidence["decision"], "layer_statuses": layers,
            "authority_boundary": boundary, "fresh_deterministic_execution": {"status": fresh["status"]}}


def _r04_scope(entry: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    _fail(evidence.get("format") == "plcman.issue32.r04-fr08-current-1128-projection/v1", "R04_PROJECTION_SCHEMA")
    _fail(entry["profile"] == R04_PROFILE, "R04_PROFILE_MISMATCH")
    scope = _mapping(_required(evidence, "scope", "R04_PROJECTION_SCHEMA"), "R04_SCOPE_SCHEMA")
    unknowns = _mapping(_required(evidence, "unknowns", "R04_PROJECTION_SCHEMA"), "R04_UNKNOWNS_SCHEMA")
    history = _mapping(_required(evidence, "historical_boundary", "R04_PROJECTION_SCHEMA"), "R04_HISTORY_SCHEMA")
    holdout = _mapping(_required(evidence, "holdout_h", "R04_PROJECTION_SCHEMA"), "R04_HOLDOUT_SCHEMA")
    regression = _mapping(_required(evidence, "regression_evidence", "R04_PROJECTION_SCHEMA"), "R04_REGRESSION_SCHEMA")
    _fail(_required(evidence, "decision", "R04_PROJECTION_SCHEMA") == R04_DECISION, "R04_PROJECTION_SCHEMA")
    return {"reference_decision": evidence["decision"], "scope": scope, "unknowns": unknowns,
            "historical_1_120": {key: _required(history, key, "R04_HISTORY_SCHEMA") for key in
                                 ("historical_gx_version", "historical_preflight_tests_run", "historical_tests_not_run",
                                  "installed_catalog_integration", "external_authority")},
            "holdout_h": {key: _required(holdout, key, "R04_HOLDOUT_SCHEMA") for key in
                          ("scope", "binding_decision", "source_compare_decision", "coverage", "authority_binding")},
            "regression_evidence": regression}


def build_report(manifest: dict[str, Any], manifest_sha256: str, artifact_root: Path) -> dict[str, Any]:
    declared_total = sum(entry["projection"]["byte_count"] for entry in manifest["profiles"])
    _fail(declared_total <= safe.MAX_ARTIFACT_TOTAL_BYTES, "PROJECTION_TOTAL_CAP")
    reports: list[dict[str, Any]] = []
    snapshots: list[tuple[Path, dict[str, Any]]] = []
    actual_total = 0
    for entry in manifest["profiles"]:
        path, fingerprint, evidence = _projection_snapshot(artifact_root, entry["projection"])
        actual_total += fingerprint["byte_count"]
        _fail(actual_total <= safe.MAX_ARTIFACT_TOTAL_BYTES, "PROJECTION_TOTAL_CAP")
        scope = _p002_scope(entry, evidence) if entry["kind"] == P002_KIND else _r04_scope(entry, evidence)
        reports.append({"profile": entry["profile"], "projection_kind": entry["kind"],
                        "projection": {"relative_path": entry["projection"]["relative_path"], **fingerprint},
                        "q_scope": entry["q_scope"], "referenced_scope": scope})
        snapshots.append((path, fingerprint))
    for path, fingerprint in snapshots:
        _fail(safe._fingerprint_file(path, safe.MAX_ARTIFACT_BYTES, "PROJECTION") == fingerprint,
              "PROJECTION_CHANGED_DURING_READ")
    return {"format": REPORT_FORMAT, "version": 1, "decision": "PROFILE_SCOPE_REFERENCED_NOT_AGGREGATED",
            "support_claim": "NOT_MADE", "issue_completion": "NOT_CLAIMED", "plc_execution": "NOT_RUN",
            "manifest": {"scope_id": manifest["scope_id"], "sha256": manifest_sha256},
            "profile_reports": reports}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest, digest = read_manifest(args.manifest, args.manifest_sha256)
        report = build_report(manifest, digest, args.artifact_root)
        payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        safe._publish_new(args.output, payload)
    except (safe.LedgerError, OSError) as error:
        print(json.dumps({"decision": "BLOCKED", "lifecycle": "NOT_RUN",
                          "blocker": error.code if isinstance(error, safe.LedgerError) else "FINAL_SCOPE_IO"}, sort_keys=True))
        return 1
    print(json.dumps({"decision": "PROFILE_SCOPE_REFERENCED_NOT_AGGREGATED", "lifecycle": "NOT_RUN",
                      "profile_count": len(report["profile_reports"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
