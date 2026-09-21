"""Deterministic, plan-only feature-model selector for GX RE Lab.

Input schema: plcman.gx-re-lab.feature-model v1 JSON.  Output schema is a
PLAN_ONLY report; this module neither interprets production inventories nor
starts a GX lifecycle.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import stat
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1_048_576
MAX_CARTESIAN_TUPLES = 10_000
MAX_AXES = 16
MAX_CONSTRAINTS = 1_024
MAX_CONSTRAINT_EVALUATIONS = 250_000
MAX_PAIR_MEMBERSHIPS = 200_000
MAX_PAIRWISE_WORK = 500_000
FORMAT = "plcman.gx-re-lab.feature-model"


class PlannerError(Exception):
    def __init__(self, code: str, reasons: list[str] | None = None) -> None:
        super().__init__(code)
        self.code, self.reasons = code, reasons or []


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PlannerError("DUPLICATE_KEY")
        value[key] = item
    return value


def _bad_constant(_: str) -> None:
    raise PlannerError("INPUT_JSON")


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _final_path(descriptor: int) -> str:
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        buffer = ctypes.create_unicode_buffer(32_768)
        get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
        get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_final_path.restype = wintypes.DWORD
        length = get_final_path(wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)), buffer, len(buffer), 0)
        if length == 0 or length >= len(buffer):
            raise OSError("final path unavailable")
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return os.path.normcase(os.path.abspath(value))
    return os.path.normcase(os.path.abspath(os.readlink(f"/proc/self/fd/{descriptor}")))


def _checked_path(path: Path) -> tuple[Path, tuple[int, int, int, int], str]:
    try:
        checked = path.absolute()
        current = checked
        while True:
            is_junction = getattr(current, "is_junction", None)
            if current.exists() and (current.is_symlink() or (callable(is_junction) and is_junction())):
                raise PlannerError("INPUT_LINK_OR_SWAP")
            if current.parent == current:
                break
            current = current.parent
        info = os.stat(checked, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise PlannerError("INPUT_CAP_OR_TYPE")
        if info.st_size > MAX_INPUT_BYTES:
            raise PlannerError("INPUT_BYTES_CAP")
        return checked, _identity(info), os.path.normcase(os.path.abspath(checked.resolve()))
    except PlannerError:
        raise
    except OSError as error:
        raise PlannerError("INPUT_UNREADABLE") from error


def load_model(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        checked, expected_identity, intended = _checked_path(path)
        descriptor = os.open(checked, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except PlannerError:
        raise
    except OSError as error:
        raise PlannerError("INPUT_LINK_OR_SWAP") from error
    try:
        opened = os.fstat(descriptor)
        final_path = _final_path(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PlannerError("INPUT_CAP_OR_TYPE")
        if opened.st_size > MAX_INPUT_BYTES:
            raise PlannerError("INPUT_BYTES_CAP")
        if _identity(opened) != expected_identity or final_path != intended:
            raise PlannerError("INPUT_LINK_OR_SWAP")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_INPUT_BYTES:
            block = os.read(descriptor, min(1_048_576, MAX_INPUT_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        if total > MAX_INPUT_BYTES:
            raise PlannerError("INPUT_BYTES_CAP")
        body = b"".join(chunks)
        path_info = os.stat(checked, follow_symlinks=False)
        if (_identity(os.fstat(descriptor)) != _identity(opened) or _final_path(descriptor) != final_path
                or _identity(path_info) != _identity(opened)
                or os.path.normcase(os.path.abspath(checked.resolve())) != final_path):
            raise PlannerError("INPUT_LINK_OR_SWAP")
    except PlannerError:
        raise
    except OSError as error:
        raise PlannerError("INPUT_LINK_OR_SWAP") from error
    finally:
        os.close(descriptor)
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicates,
                           parse_constant=_bad_constant)
    except PlannerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PlannerError("INPUT_JSON") from error
    if not isinstance(value, dict):
        raise PlannerError("MODEL_SCHEMA")
    return value, {"byte_count": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _require(condition: bool) -> None:
    if not condition:
        raise PlannerError("MODEL_SCHEMA")


def _validate(model: dict[str, Any]) -> tuple[list[str], list[list[str]], list[dict[str, Any]]]:
    required = {"format", "version", "seed", "mode", "axes", "constraints"}
    _require(set(model) in (required, required | {"inventory_reference"}))
    _require(model["format"] == FORMAT and type(model["version"]) is int and model["version"] == 1)
    _require(type(model["seed"]) is int and 0 <= model["seed"] <= 0xFFFFFFFF)
    _require(model["mode"] in ("exhaustive", "pairwise") and isinstance(model["axes"], list)
             and model["axes"] and len(model["axes"]) <= MAX_AXES)
    names: list[str] = []
    values: list[list[str]] = []
    for axis in model["axes"]:
        _require(isinstance(axis, dict) and set(axis) == {"name", "values"})
        name, options = axis["name"], axis["values"]
        _require(isinstance(name, str) and name and len(name) <= 64 and isinstance(options, list) and options)
        _require(all(isinstance(option, str) and option and len(option) <= 128 for option in options))
        _require(name not in names and len(set(options)) == len(options))
        names.append(name)
        values.append(options)
    _require(isinstance(model["constraints"], list) and len(model["constraints"]) <= MAX_CONSTRAINTS)
    known = dict(zip(names, values))
    constraints: list[dict[str, Any]] = []
    for constraint in model["constraints"]:
        _require(isinstance(constraint, dict) and set(constraint) == {"when", "reason"})
        when, reason = constraint["when"], constraint["reason"]
        _require(isinstance(when, dict) and when and isinstance(reason, str) and reason and len(reason) <= 256)
        _require(all(isinstance(key, str) and key in known and isinstance(item, str) and item in known[key]
                     for key, item in when.items()))
        constraints.append(constraint)
    if "inventory_reference" in model:
        reference = model["inventory_reference"]
        _require(isinstance(reference, dict) and set(reference) == {"path", "sha256"})
        _require(isinstance(reference["path"], str) and reference["path"] and isinstance(reference["sha256"], str))
        _require(len(reference["sha256"]) == 64 and all(char in "0123456789abcdef" for char in reference["sha256"]))
    count = 1
    for options in values:
        count *= len(options)
        if count > MAX_CARTESIAN_TUPLES:
            raise PlannerError("CARTESIAN_CAP")
    if count * len(constraints) > MAX_CONSTRAINT_EVALUATIONS:
        raise PlannerError("CONSTRAINT_WORK_CAP")
    if count * (len(names) * (len(names) - 1) // 2) > MAX_PAIR_MEMBERSHIPS:
        raise PlannerError("PAIR_MEMBERSHIP_CAP")
    return names, values, constraints


def _tuple_key(features: dict[str, str]) -> str:
    return json.dumps(features, ensure_ascii=False, separators=(",", ":"))


def _pairs(features: dict[str, str], names: list[str]) -> set[tuple[str, str, str, str]]:
    return {(names[left], features[names[left]], names[right], features[names[right]])
            for left in range(len(names)) for right in range(left + 1, len(names))}


def plan(model: dict[str, Any]) -> dict[str, Any]:
    names, options, constraints = _validate(model)
    possible = [dict(zip(names, row)) for row in itertools.product(*options)]
    excluded: list[dict[str, Any]] = []
    eligible: list[dict[str, str]] = []
    for features in possible:
        reasons = [constraint["reason"] for constraint in constraints
                   if all(features[key] == item for key, item in constraint["when"].items())]
        if reasons:
            excluded.append({"features": features, "reasons": reasons})
        else:
            eligible.append(features)
    if not eligible:
        raise PlannerError("NO_ELIGIBLE_TUPLES", [item["reason"] for item in constraints])
    candidates = [(features, _pairs(features, names)) for features in eligible]
    denominator = set().union(*(item[1] for item in candidates))
    if model["mode"] == "exhaustive":
        selected_entries = candidates
    else:
        seed = model["seed"]
        ordered = sorted(candidates, key=lambda item: hashlib.sha256(
            f"{seed}:{_tuple_key(item[0])}".encode("utf-8")).digest())
        remaining, selected_entries = set(denominator), []
        work = 0
        while remaining:
            candidate_index, candidate_score = 0, -1
            for index, (_, pair_set) in enumerate(ordered):
                work += len(pair_set)
                if work > MAX_PAIRWISE_WORK:
                    raise PlannerError("PAIRWISE_WORK_CAP")
                score = len(pair_set & remaining)
                if score > candidate_score:
                    candidate_index, candidate_score = index, score
            candidate, pair_set = ordered.pop(candidate_index)
            selected_entries.append((candidate, pair_set))
            remaining -= pair_set
        if not selected_entries:
            selected_entries.append(ordered[0])
    selected = [item[0] for item in selected_entries]
    covered = set().union(*(item[1] for item in selected_entries))
    report: dict[str, Any] = {
        "format": "plcman.gx-re-lab.plan-report", "version": 1,
        "decision": "PLAN_ONLY", "lifecycle": "NOT_RUN", "mode": model["mode"], "seed": model["seed"],
        "axes": names, "tuple_counts": {"possible": len(possible), "excluded": len(excluded),
                                              "eligible": len(eligible), "planned": len(selected), "executed": 0,
                                              "verified": 0, "unverified": len(eligible)},
        "pair_counts": {"denominator": len(denominator), "planned": len(covered),
                        "uncovered": len(denominator - covered), "unverified": len(denominator)},
        "excluded": excluded, "planned": selected,
    }
    if "inventory_reference" in model:
        report["inventory_reference"] = model["inventory_reference"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        model, fingerprint = load_model(args.model)
        report = plan(model)
        report["input"] = fingerprint
    except PlannerError as error:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": [error.code]}
        if error.reasons:
            report["constraint_reasons"] = error.reasons
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["decision"] == "PLAN_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
