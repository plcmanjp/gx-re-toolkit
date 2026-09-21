"""Pinned no-op/single-cell relations over independently verified source cases.

This is a read-only research replay comparator, not an editor or lifecycle runner.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import lab
from .table_delta import table_delta


def _schema(condition: bool) -> None:
    if not condition:
        raise lab.LabError("EXPERIMENT_SCHEMA")


def read_experiment(path: Path, pin: str) -> dict:
    _schema(isinstance(pin, str) and len(pin) == 64 and all(c in "0123456789abcdef" for c in pin))
    body, digest = lab._retained_bytes(path, "--experiment", lab.MAX_MANIFEST_BYTES)
    if digest != pin:
        raise lab.LabError("EXPERIMENT_PIN_MISMATCH")
    value = lab._json_no_duplicates(body)
    _schema(set(value) == {"format", "version", "experiment_id", "seed", "mode", "before_case_sha256", "after_case_sha256", "change"})
    _schema(value["format"] == "plcman.gx-re-lab.experiment" and type(value["version"]) is int and value["version"] == 1)
    _schema(isinstance(value["experiment_id"], str) and bool(lab.CASE_ID.fullmatch(value["experiment_id"])))
    _schema(type(value["seed"]) is int and 0 <= value["seed"] <= 0xFFFFFFFF)
    for key in ("before_case_sha256", "after_case_sha256"):
        item = value[key]
        _schema(isinstance(item, str) and len(item) == 64 and all(c in "0123456789abcdef" for c in item))
    _schema(value["mode"] in ("no_op", "single_cell"))
    change = value["change"]
    if value["mode"] == "no_op":
        _schema(change is None)
    else:
        _schema(isinstance(change, dict) and set(change) == {"row", "column", "before", "after"})
        _schema(type(change["row"]) is int and change["row"] >= 0)
        _schema(type(change["column"]) is int and 0 <= change["column"] < 7)
        _schema(type(change["before"]) is str and type(change["after"]) is str and change["before"] != change["after"])
    return value


def compare_relation(experiment: dict, before: dict, after: dict) -> dict:
    """Only call with pinned case manifests whose source/export verify succeeded."""
    if (before["profile"] != after["profile"] or
            before["expected"]["pous"] != after["expected"]["pous"] or
            before["expected"]["selected_pou_id"] != after["expected"]["selected_pou_id"]):
        raise lab.LabError("EXPERIMENT_TOPOLOGY_MISMATCH")
    rows_before, rows_after = before["expected"]["rows"], after["expected"]["rows"]
    delta = table_delta(rows_before, rows_after)
    if delta["added_rows"] or delta["removed_rows"]:
        raise lab.LabError("EXPERIMENT_ROW_COUNT_MISMATCH")
    if experiment["mode"] == "no_op":
        if delta["changed_cells"]:
            raise lab.LabError("EXPERIMENT_UNEXPECTED_CHANGE")
    else:
        change = experiment["change"]
        row, column = change["row"], change["column"]
        if (delta["changed_cells"] != [[row, column]] or
                rows_before[row][column] != change["before"] or
                rows_after[row][column] != change["after"]):
            raise lab.LabError("EXPERIMENT_UNEXPECTED_CHANGE")
    return delta


def verify_experiment(path: Path, pin: str, before_paths: tuple[Path, Path, Path], after_paths: tuple[Path, Path, Path]) -> dict:
    experiment = read_experiment(path, pin)
    manifests, reports = [], []
    for prefix, paths in (("before", before_paths), ("after", after_paths)):
        case, source, export = paths
        case_pin = experiment[f"{prefix}_case_sha256"]
        reports.append(lab.verify(case, case_pin, source, export))
        # Re-read only against the same external pin; never derive expectations from IR.
        manifests.append(lab._read_manifest(case, case_pin))
    delta = compare_relation(experiment, *manifests)
    if read_experiment(path, pin) != experiment:
        raise lab.LabError("EXPERIMENT_PIN_MISMATCH")
    return {
        "format": "plcman.gx-re-lab.experiment-report", "version": 1,
        "experiment_id": experiment["experiment_id"], "experiment_sha256": pin,
        "seed": experiment["seed"], "mode": experiment["mode"],
        "decision": "RELATION_MATCH", "evidence_mode": "REPLAY_ONLY", "lifecycle": "NOT_RUN",
        "delta": delta, "cases": reports,
        "execution": {"experiment_code_sha256": lab._sha256_bytes(Path(__file__).read_bytes()),
                      "delta_code_sha256": lab._sha256_bytes(Path(__file__).with_name("table_delta.py").read_bytes())},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", required=True, type=Path)
    parser.add_argument("--experiment-sha256", required=True)
    for prefix in ("before", "after"):
        for kind in ("case", "source", "export"):
            parser.add_argument(f"--{prefix}-{kind}", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_experiment(args.experiment, args.experiment_sha256,
                                   (args.before_case, args.before_source, args.before_export),
                                   (args.after_case, args.after_source, args.after_export))
    except lab.LabError as error:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": [error.code]}
    except Exception:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": ["EXPERIMENT_BLOCKED"]}
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["decision"] == "RELATION_MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
