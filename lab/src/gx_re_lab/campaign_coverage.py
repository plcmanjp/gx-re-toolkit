"""Read-only coverage audit for individually evidenced FX5U campaign cases.

The original planner remains ``PLAN_ONLY``.  This adapter separately counts a
planned tuple only when a final campaign report is tied, by pinned artifacts,
to its invocation, campaign/recipe/template inputs, lifecycle report, case
manifest, source comparison and lifecycle binding report.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


MAX_JSON = 1024 * 1024
MAX_ARTIFACT = 16 * 1024 * 1024
MAX_DEPTH = 32
HEX = set("0123456789abcdef")
RUNTIME_ARTIFACT_KEYS = {"campaign", "intended_csv", "plan", "recipe", "source", "template"}
LEGACY_RUNTIME_TOOL_KEYS = {
    "binder_tool", "campaign_tool", "gx_executable_tool", "lab_tool", "lifecycle_tool",
    "menu_path_identity_tool", "native_export_file_tool", "native_file_dialog_tool",
    "native_import_confirm_tool", "native_import_file_tool", "native_offline_dialogs_tool",
    "native_startup_notice_tool", "semantic_menu_runner_tool",
}
FOCUSED_RUNTIME_TOOL_KEYS = LEGACY_RUNTIME_TOOL_KEYS | {"startup_focus_tool"}
STARTUP_FOCUS_METHODS = {"passive", "uia-set-focus"}


class CoverageError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Snapshot:
    body: bytes
    fingerprint: dict[str, Any]
    identity: tuple[int, int, int, int]


def _fail(condition: bool, code: str) -> None:
    if not condition:
        raise CoverageError(code)


def _pin(value: object, code: str = "PIN_SCHEMA") -> str:
    _fail(isinstance(value, str) and len(value) == 64 and set(value) <= HEX, code)
    return value


def _fp(body: bytes) -> dict[str, Any]:
    return {"byte_count": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _link_like(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


def _read(path: Path, label: str, cap: int = MAX_JSON) -> Snapshot:
    absolute = Path(path).absolute()
    _fail(not any(_link_like(item) for item in (absolute, *absolute.parents)), label + "_LINK")
    try:
        before = os.lstat(absolute)
        _fail(stat.S_ISREG(before.st_mode) and before.st_size <= cap, label + "_TYPE_OR_CAP")
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except CoverageError:
        raise
    except OSError as error:
        raise CoverageError(label + "_IO") from error
    try:
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        _fail(identity == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns), label + "_SWAP")
        chunks: list[bytes] = []
        total = 0
        while total <= cap:
            block = os.read(descriptor, min(1024 * 1024, cap + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        _fail(total <= cap, label + "_TYPE_OR_CAP")
        body = b"".join(chunks)
        after, path_after = os.fstat(descriptor), os.lstat(absolute)
        _fail(identity == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
              identity == (path_after.st_dev, path_after.st_ino, path_after.st_size, path_after.st_mtime_ns), label + "_SWAP")
        return Snapshot(body, _fp(body), identity)
    finally:
        os.close(descriptor)


def _verify(path: Path, label: str, expected: Snapshot, cap: int = MAX_ARTIFACT) -> None:
    current = _read(path, label, cap)
    _fail(current.fingerprint == expected.fingerprint and current.identity == expected.identity, label + "_CHANGED")


def _json(snapshot: Snapshot, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise CoverageError(label + "_DUPLICATE")
            result[key] = value
        return result
    try:
        value = json.loads(snapshot.body.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(CoverageError(label + "_NONFINITE")))
    except CoverageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise CoverageError(label + "_JSON") from error
    _fail(isinstance(value, dict), label + "_SCHEMA")
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        _fail(depth <= MAX_DEPTH, label + "_DEPTH")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _fingerprint(value: object, code: str) -> dict[str, Any]:
    _fail(isinstance(value, dict) and set(value) == {"byte_count", "sha256"} and
          type(value["byte_count"]) is int and value["byte_count"] >= 0, code)
    _pin(value["sha256"], code)
    return value


def _same_fp(actual: Snapshot, declared: object, code: str) -> None:
    _fail(actual.fingerprint == _fingerprint(declared, code), code)


def _runtime(value: object, label: str) -> dict[str, dict[str, Any]]:
    _fail(isinstance(value, dict), label + "_SCHEMA")
    tool_keys = set(value) - RUNTIME_ARTIFACT_KEYS
    _fail(set(value) == RUNTIME_ARTIFACT_KEYS | tool_keys and
          tool_keys in (LEGACY_RUNTIME_TOOL_KEYS, FOCUSED_RUNTIME_TOOL_KEYS), label + "_SCHEMA")
    return {key: _fingerprint(item, label + "_SCHEMA") for key, item in value.items()}


def _runtime_tool_keys(runtime: dict[str, dict[str, Any]]) -> set[str]:
    return set(runtime) - RUNTIME_ARTIFACT_KEYS


def _startup_focus_method(campaign: dict[str, Any]) -> str:
    lifecycle = campaign.get("lifecycle")
    _fail(isinstance(lifecycle, dict), "CAMPAIGN_LIFECYCLE_SCHEMA")
    method = lifecycle.get("startup_focus_method", "passive")
    _fail(method in STARTUP_FOCUS_METHODS, "CAMPAIGN_LIFECYCLE_SCHEMA")
    return method


def _unfinished(value: object) -> bool:
    if isinstance(value, dict):
        if value.get("status") in {"PENDING", "BLOCKED", "FAILED", "TIMEOUT"}:
            return True
        if value.get("phase") in {"FAILED", "TIMEOUT"}:
            return True
        return any(_unfinished(item) for item in value.values())
    if isinstance(value, list):
        return any(_unfinished(item) for item in value)
    return False


def _lifecycle_state(lifecycle: dict[str, Any], *, seed: Snapshot, intended: Snapshot, saved: Snapshot) -> None:
    required = {"format", "version", "status", "comparison", "hash", "expected_editor_titles",
                "action", "effect", "owned_processes", "owned_processes_reaped", "report_path"}
    _fail(set(lifecycle) in (required, required | {"reason"}), "LIFECYCLE_SCHEMA")
    _fail((lifecycle.get("format"), lifecycle.get("version"), lifecycle.get("status")) ==
          ("plcman.issue32.offline-lifecycle", 1, "LIFECYCLE_ARTIFACT_OBSERVED"), "LIFECYCLE_SCHEMA")
    _fail(lifecycle.get("comparison") == {"status": "NOT_RUN", "reason": "official CSV comparison is an independent gate"},
          "LIFECYCLE_SCHEMA")
    titles = lifecycle.get("expected_editor_titles")
    _fail(isinstance(titles, dict) and set(titles) == {"initial", "post_import", "post_rebuild", "post_save", "reopen"} and
          all(isinstance(value, str) and value for value in titles.values()), "LIFECYCLE_SCHEMA")
    hashes = lifecycle.get("hash")
    hash_keys = {"source_before", "csv_before", "copy_before", "copy_after_save", "copy_pre_reopen",
                 "source_after", "csv_after", "copy_final", "source_final", "csv_final"}
    _fail(isinstance(hashes, dict) and hash_keys <= set(hashes) and all(isinstance(hashes[key], str) and len(hashes[key]) == 64 and set(hashes[key]) <= HEX for key in hash_keys),
          "LIFECYCLE_HASHES")
    _fail(hashes["source_before"] == hashes["source_after"] == hashes["source_final"] == seed.fingerprint["sha256"] and
          hashes["csv_before"] == hashes["csv_after"] == hashes["csv_final"] == intended.fingerprint["sha256"] and
          hashes["copy_before"] == seed.fingerprint["sha256"] and
          hashes["copy_after_save"] == hashes["copy_pre_reopen"] == hashes["copy_final"] == saved.fingerprint["sha256"],
          "LIFECYCLE_HASHES")
    stages = {"semantic_child_preflight", "startup_notice", "compression", "import", "rebuild", "save", "reopen_startup_notice", "reopen_compression", "export"}
    action, effect = lifecycle.get("action"), lifecycle.get("effect")
    _fail(isinstance(action, dict) and all(isinstance(action.get(key), dict) and action[key] for key in stages) and not _unfinished(action),
          "LIFECYCLE_ACTION_INCOMPLETE")
    effect_keys = {"initial_editor", "startup_notice_transition", "import", "post_import_editor", "rebuild", "post_rebuild_editor", "save", "post_save_editor", "first_close", "reopen_startup_notice_transition", "reopen_editor", "export", "second_close"}
    _fail(isinstance(effect, dict) and all(effect.get(key) for key in effect_keys) and not _unfinished(effect) and
          effect.get("first_close") == "GRACEFUL_EXIT" and effect.get("second_close") == "GRACEFUL_EXIT", "LIFECYCLE_EFFECT_INCOMPLETE")
    processes = lifecycle.get("owned_processes")
    _fail(lifecycle.get("owned_processes_reaped") is True and isinstance(processes, list) and len(processes) == 2 and
          all(isinstance(row, dict) and type(row.get("pid")) is int and row["pid"] > 0 for row in processes) and
          {row.get("role") for row in processes} == {"lifecycle", "reopen_export"} and len({row["pid"] for row in processes}) == 2,
          "LIFECYCLE_REAP_INCOMPLETE")


def _observed_run_digest(lifecycle: dict[str, Any], *, seed: Snapshot, saved: Snapshot, exported: Snapshot) -> str:
    """Bind an observed run without mutable report location or JSON formatting."""
    processes = lifecycle["owned_processes"]
    payload = {
        "format": lifecycle["format"], "version": lifecycle["version"], "status": lifecycle["status"],
        "processes": sorted(({"role": row["role"], "pid": row["pid"]} for row in processes), key=lambda row: row["role"]),
        "seed_source": seed.fingerprint, "saved_source": saved.fingerprint, "official_export": exported.fingerprint,
        "hash": lifecycle["hash"], "expected_editor_titles": lifecycle["expected_editor_titles"],
        "action_trace_witness": lifecycle["action"], "effect_witness": lifecycle["effect"],
    }
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _plan(value: dict[str, Any]) -> list[dict[str, str]]:
    keys = {"format", "version", "decision", "lifecycle", "mode", "seed", "axes", "tuple_counts", "pair_counts", "excluded", "planned", "input"}
    _fail((set(value) == keys or set(value) == keys | {"inventory_reference"}) and
          value.get("format") == "plcman.gx-re-lab.plan-report" and value.get("version") == 1 and
          value.get("decision") == "PLAN_ONLY" and value.get("lifecycle") == "NOT_RUN", "PLAN_SCHEMA")
    _fail(value.get("axes") == ["profile", "recipe"] and isinstance(value.get("planned"), list), "PLAN_SCHEMA")
    counts = value.get("tuple_counts")
    _fail(isinstance(counts, dict) and set(counts) == {"possible", "excluded", "eligible", "planned", "executed", "verified", "unverified"} and
          all(type(item) is int and item >= 0 for item in counts.values()) and counts["planned"] == len(value["planned"]), "PLAN_SCHEMA")
    planned: list[dict[str, str]] = []
    for candidate in value["planned"]:
        _fail(isinstance(candidate, dict) and set(candidate) == {"profile", "recipe"} and
              all(isinstance(item, str) and item for item in candidate.values()), "PLAN_SCHEMA")
        planned.append({"profile": candidate["profile"], "recipe": candidate["recipe"]})
    _fail(len({tuple(item.items()) for item in planned}) == len(planned), "PLAN_DUPLICATE_TUPLE")
    return planned


def _required(root: Path, name: str) -> Path:
    path = Path(root) / name
    _fail(path.parent == Path(root), "CASE_PATH")
    return path


def _validate_case(plan_snapshot: Snapshot, planned: list[dict[str, str]], case_root: Path, input_root: Path,
                   intended_path: Path, seed_path: Path, report_sha256: str) -> tuple[int, dict[str, Any], list[tuple[Path, str, Snapshot]], str]:
    _pin(report_sha256, "EXTERNAL_REPORT_PIN_SCHEMA")
    names = {
        "campaign_report": (case_root, "campaign-report.json"), "invocation": (case_root, "invocation.json"),
        "binding": (case_root, "binding-report.json"), "case": (case_root, "case-manifest.json"),
        "lab": (case_root, "lab-report.json"), "lifecycle": (Path(case_root) / "lifecycle", "report.json"),
        "campaign": (input_root, "campaign.json"), "recipe": (input_root, "recipe.json"), "template": (input_root, "template.json"),
    }
    snapshots: dict[str, Snapshot] = {}
    report_path = _required(case_root, "campaign-report.json")
    retained: list[tuple[Path, str, Snapshot]] = [(report_path, "CAMPAIGN_REPORT", _read(report_path, "CAMPAIGN_REPORT"))]
    snapshots["campaign_report"] = retained[0][2]
    _fail(snapshots["campaign_report"].fingerprint["sha256"] == report_sha256, "EXTERNAL_REPORT_PIN")
    for label, (root, filename) in names.items():
        if label == "campaign_report":
            continue
        path = Path(root) / filename
        snapshot = _read(path, label.upper())
        snapshots[label] = snapshot
        retained.append((path, label.upper(), snapshot))
    report = _json(snapshots["campaign_report"], "CAMPAIGN_REPORT")
    _fail(set(report) == {"campaign_mapping", "decision", "format", "full_authority", "identity", "plan_execution", "plc_execution", "scope", "source_comparison", "support_claim", "typed_device_or_form", "version"} and
          report.get("format") == "plcman.gx-re-lab.fx5u-1.128-campaign-report" and report.get("version") == 1 and
          report.get("decision") == "CASE_EXECUTION_OBSERVED" and report.get("campaign_mapping") == "PINNED_INVOCATION_BOUND" and
          report.get("plan_execution") == "NOT_BOUND" and report.get("source_comparison") == "SOURCE_MATCH" and
          report.get("full_authority") == "NOT_MADE" and report.get("support_claim") == "NOT_MADE" and report.get("plc_execution") == "NOT_RUN", "CAMPAIGN_REPORT_SCHEMA")
    identity = report.get("identity")
    _fail(isinstance(identity, dict) and set(identity) == {"binding_report", "case_manifest", "invocation", "lab_report", "lifecycle_report", "official_export", "runtime_post", "runtime_pre", "saved_source"}, "CAMPAIGN_REPORT_SCHEMA")
    for key, artifact in (("invocation", "invocation"), ("lifecycle_report", "lifecycle"), ("case_manifest", "case"),
                          ("lab_report", "lab"), ("binding_report", "binding")):
        _same_fp(snapshots[artifact], identity.get(key), "CAMPAIGN_REPORT_BINDING")
    runtime_pre, runtime_post = _runtime(identity.get("runtime_pre"), "CAMPAIGN_RUNTIME") , _runtime(identity.get("runtime_post"), "CAMPAIGN_RUNTIME")
    _fail(runtime_pre == runtime_post, "CAMPAIGN_RUNTIME_DRIFT")
    runtime_tool_keys = _runtime_tool_keys(runtime_pre)
    intended, seed = _read(intended_path, "INTENDED_CSV", MAX_ARTIFACT), _read(seed_path, "SEED_SOURCE", MAX_ARTIFACT)
    retained.extend(((Path(intended_path), "INTENDED_CSV", intended), (Path(seed_path), "SEED_SOURCE", seed)))
    for key, snapshot in (("campaign", snapshots["campaign"]), ("intended_csv", intended), ("plan", plan_snapshot),
                          ("recipe", snapshots["recipe"]), ("source", seed), ("template", snapshots["template"])):
        _same_fp(snapshot, runtime_pre[key], "CAMPAIGN_RUNTIME_BINDING")
    invocation = _json(snapshots["invocation"], "INVOCATION")
    _fail(invocation.get("format") == "plcman.gx-re-lab.campaign-invocation" and invocation.get("version") == 1 and
          type(invocation.get("planned_index")) is int, "INVOCATION_SCHEMA")
    index = invocation["planned_index"]
    _fail(0 <= index < len(planned), "PLAN_INDEX")
    _same_fp(plan_snapshot, invocation.get("plan"), "INVOCATION_PLAN")
    for key in ("campaign", "recipe", "template"):
        _same_fp(snapshots[key], invocation.get(key), "INVOCATION_BINDING")
    _same_fp(intended, invocation.get("intended_csv"), "INVOCATION_INTENDED_BINDING")
    _same_fp(seed, invocation.get("source"), "INVOCATION_SEED_BINDING")
    tools = invocation.get("tool_sha256")
    _fail(isinstance(tools, dict) and set(tools) == {key.removesuffix("_tool") for key in runtime_tool_keys} and
          all(isinstance(value, str) and len(value) == 64 and set(value) <= HEX for value in tools.values()), "INVOCATION_TOOL_SCHEMA")
    for key in runtime_tool_keys:
        _fail(runtime_pre[key]["sha256"] == tools[key.removesuffix("_tool")] and runtime_pre[key]["byte_count"] > 0,
              "CAMPAIGN_RUNTIME_TOOL_BINDING")
    campaign, recipe, template = (_json(snapshots[key], key.upper()) for key in ("campaign", "recipe", "template"))
    _fail(campaign.get("format") == "plcman.gx-re-lab.fx5u-1.128-offline-campaign" and campaign.get("version") == 1 and
          isinstance(campaign.get("plan"), dict) and campaign["plan"].get("planned_index") == index and
          campaign["plan"].get("tuple_features") == planned[index], "CAMPAIGN_PLAN_TUPLE")
    _same_fp(plan_snapshot, {"byte_count": plan_snapshot.fingerprint["byte_count"], "sha256": campaign["plan"].get("sha256")}, "CAMPAIGN_PLAN_BINDING")
    _fail(campaign.get("recipe") == {"sha256": snapshots["recipe"].fingerprint["sha256"]} and
          campaign.get("case_template", {}).get("sha256") == snapshots["template"].fingerprint["sha256"], "CAMPAIGN_INPUT_BINDING")
    startup_focus_method = _startup_focus_method(campaign)
    expected_tool_keys = FOCUSED_RUNTIME_TOOL_KEYS if startup_focus_method == "uia-set-focus" else LEGACY_RUNTIME_TOOL_KEYS
    _fail(runtime_tool_keys == expected_tool_keys, "CAMPAIGN_FOCUS_TOOLSET")
    _fail(recipe.get("format") == "plcman.gx-re-lab.fx5u-1.128-offline-recipe" and recipe.get("version") == 1 and
          recipe.get("tuple_features") == planned[index], "RECIPE_PLAN_TUPLE")
    _fail(recipe.get("lifecycle") == campaign.get("lifecycle"), "RECIPE_CAMPAIGN_LIFECYCLE")
    _fail(template.get("format") == "plcman.gx-re-lab.case-manifest" and template.get("version") == 1, "TEMPLATE_SCHEMA")
    lifecycle_settings = campaign.get("lifecycle")
    _fail(isinstance(lifecycle_settings, dict) and isinstance(lifecycle_settings.get("copy_name"), str) and
          isinstance(lifecycle_settings.get("export_name"), str) and
          Path(lifecycle_settings["copy_name"]).name == lifecycle_settings["copy_name"] and
          Path(lifecycle_settings["export_name"]).name == lifecycle_settings["export_name"], "CAMPAIGN_LIFECYCLE_SCHEMA")
    saved_path = Path(case_root) / "lifecycle" / lifecycle_settings["copy_name"]
    export_path = Path(case_root) / "lifecycle" / lifecycle_settings["export_name"]
    saved, exported = _read(saved_path, "SAVED_SOURCE", MAX_ARTIFACT), _read(export_path, "OFFICIAL_EXPORT", MAX_ARTIFACT)
    retained.extend(((saved_path, "SAVED_SOURCE", saved), (export_path, "OFFICIAL_EXPORT", exported)))
    _same_fp(saved, identity.get("saved_source"), "CAMPAIGN_SAVED_SOURCE_BINDING")
    _same_fp(exported, identity.get("official_export"), "CAMPAIGN_EXPORT_BINDING")
    binding = _json(snapshots["binding"], "BINDING")
    _fail(binding.get("format") == "plcman.gx-re-lab.lifecycle-binding-report" and binding.get("version") == 1 and
          binding.get("decision") == "LIFECYCLE_EVIDENCE_BOUND" and binding.get("lifecycle") == "OBSERVED", "BINDING_SCHEMA")
    candidate = binding.get("candidate")
    _fail(isinstance(candidate, dict) and candidate.get("planned_index") == index and candidate.get("features") == planned[index] and
          candidate.get("execution_mapping") == "NOT_BOUND", "BINDING_PLAN_TUPLE")
    binding_identity = binding.get("identity")
    _fail(isinstance(binding_identity, dict) and set(binding_identity) == {"case_manifest", "intended_csv", "lab_report", "lifecycle_report", "official_export", "plan_report", "source"}, "BINDING_SCHEMA")
    for key, artifact in (("plan_report", None), ("lifecycle_report", "lifecycle"), ("case_manifest", "case"), ("lab_report", "lab")):
        expected = plan_snapshot if artifact is None else snapshots[artifact]
        _same_fp(expected, binding_identity.get(key), "BINDING_ARTIFACT_BINDING")
    _same_fp(saved, binding_identity.get("source"), "BINDING_SOURCE_BINDING")
    _same_fp(exported, binding_identity.get("official_export"), "BINDING_EXPORT_BINDING")
    _same_fp(intended, binding_identity.get("intended_csv"), "BINDING_INTENDED_BINDING")
    lab = _json(snapshots["lab"], "LAB")
    case = _json(snapshots["case"], "CASE")
    _fail(case.get("format") == "plcman.gx-re-lab.case-manifest" and case.get("version") == 1 and
          all(case.get(key) == template.get(key) for key in ("case_id", "profile", "expected")), "CASE_TEMPLATE_BINDING")
    _same_fp(saved, case.get("source"), "CASE_SOURCE_BINDING")
    case_export = case.get("official_export")
    _fail(isinstance(case_export, dict), "CASE_EXPORT_BINDING")
    _same_fp(exported, {"byte_count": case_export.get("byte_count"), "sha256": case_export.get("sha256")}, "CASE_EXPORT_BINDING")
    execution = lab.get("execution")
    _fail(lab.get("decision") == "SOURCE_MATCH" and lab.get("lifecycle") == "NOT_RUN" and
          lab.get("case_id") == case.get("case_id") == binding.get("case_id") and
          lab.get("selected_pou_id") == case["expected"].get("selected_pou_id") and isinstance(execution, dict), "LAB_CASE_BINDING")
    _same_fp(snapshots["case"], execution.get("manifest"), "LAB_MANIFEST_BINDING")
    _same_fp(saved, execution.get("source"), "LAB_SOURCE_BINDING")
    _same_fp(exported, execution.get("official_export"), "LAB_EXPORT_BINDING")
    lifecycle = _json(snapshots["lifecycle"], "LIFECYCLE")
    _lifecycle_state(lifecycle, seed=seed, intended=intended, saved=saved)
    return index, {"planned_index": index, "tuple_features": planned[index], "case_id": case["case_id"],
                   "campaign_report": snapshots["campaign_report"].fingerprint}, retained, _observed_run_digest(
                       lifecycle, seed=seed, saved=saved, exported=exported)


def audit(plan_path: Path, plan_sha256: str, cases: list[tuple[Path, Path, Path, Path, str]]) -> dict[str, Any]:
    _pin(plan_sha256)
    plan_snapshot = _read(plan_path, "PLAN")
    _fail(plan_snapshot.fingerprint["sha256"] == plan_sha256, "PLAN_PIN")
    plan = _json(plan_snapshot, "PLAN")
    planned = _plan(plan)
    _fail(isinstance(cases, list) and cases, "CASE_SET_SCHEMA")
    counted: list[dict[str, Any]] = []
    retained: list[tuple[Path, str, Snapshot]] = [(Path(plan_path), "PLAN", plan_snapshot)]
    indexes: set[int] = set()
    lifecycle_digests: set[str] = set()
    for case_root, input_root, intended_path, seed_path, report_sha256 in cases:
        index, item, snapshots, lifecycle_digest = _validate_case(plan_snapshot, planned, Path(case_root), Path(input_root), Path(intended_path), Path(seed_path), report_sha256)
        _fail(lifecycle_digest not in lifecycle_digests, "DUPLICATE_LIFECYCLE_REPORT")
        lifecycle_digests.add(lifecycle_digest)
        _fail(index not in indexes, "DUPLICATE_EXECUTION_TUPLE")
        indexes.add(index); counted.append(item); retained.extend(snapshots)
    for path, label, snapshot in retained:
        _verify(path, label, snapshot)
    original = plan["tuple_counts"]
    audited = {"possible": original["possible"], "excluded": original["excluded"], "eligible": original["eligible"],
               "planned": len(planned), "executed": len(counted), "verified": len(counted), "unverified": len(planned) - len(counted)}
    return {"format": "plcman.gx-re-lab.campaign-coverage-report", "version": 1,
            "decision": "AUDITED_COVERAGE_OBSERVED", "planner_status": "PLAN_ONLY_UNCHANGED",
            "coverage_status": "SEPARATE_READONLY_AUDIT", "plan": plan_snapshot.fingerprint,
            "tuple_counts": audited, "executed_cases": sorted(counted, key=lambda item: item["planned_index"]),
            "verification_basis": "EXTERNALLY_PINNED_HISTORICAL_EVIDENCE", "fresh_binder_execution": "NOT_RUN",
            "full_authority": "NOT_MADE", "support_claim": "NOT_MADE", "plc_execution": "NOT_RUN"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-report", required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--case-root", required=True, type=Path, action="append")
    parser.add_argument("--campaign-input-root", required=True, type=Path, action="append")
    parser.add_argument("--intended-csv", required=True, type=Path, action="append")
    parser.add_argument("--seed-source", required=True, type=Path, action="append")
    parser.add_argument("--campaign-report-sha256", required=True, action="append")
    args = parser.parse_args(argv)
    try:
        _fail(len({len(args.case_root), len(args.campaign_input_root), len(args.intended_csv), len(args.seed_source), len(args.campaign_report_sha256)}) == 1, "CASE_SET_SCHEMA")
        result = audit(args.plan_report, args.plan_sha256, list(zip(args.case_root, args.campaign_input_root, args.intended_csv, args.seed_source, args.campaign_report_sha256, strict=True)))
    except CoverageError as error:
        result = {"decision": "BLOCKED", "blockers": [error.code], "planner_status": "PLAN_ONLY_UNCHANGED"}
    except Exception:
        result = {"decision": "BLOCKED", "blockers": ["COVERAGE_AUDIT_FAILED"], "planner_status": "PLAN_ONLY_UNCHANGED"}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if result["decision"] == "AUDITED_COVERAGE_OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
