"""Pinned, bounded corpus census; structural observations are not acceptance.

Manifest v1 contains anonymized case IDs, relative paths, adapter names,
byte counts and SHA-256 pins. Every occurrence (including duplicate inputs)
is processed. A failed case remains in the report. Reused container keys are
compared by content hash, never treated as global semantic identities.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import tempfile
import zipfile

from .lab import LabError, CASE_ID, _json_no_duplicates, _retained_bytes
from .snapshot import _reject_link_like_ancestors
from . import census as fx5, gxw_census as gxw
from .gxw_census import _publish_json

FORMAT = "plcman.gx-re-lab.corpus-manifest"
MAX_CASES = 256
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_KEYS = 65536
ADAPTERS = {"GX3-FX5": fx5.census, "GXW-Q": gxw.census}
SUFFIXES = {"GX3-FX5": ".gx3", "GXW-Q": ".gxw"}


def _fail(condition: bool, code: str) -> None:
    if not condition:
        raise LabError(code)


def _pin(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= set("0123456789abcdef")


def validate_manifest(value: dict) -> list[dict]:
    _fail(set(value) == {"format", "version", "cases"} and value["format"] == FORMAT
          and type(value["version"]) is int and value["version"] == 1, "CORPUS_SCHEMA")
    cases = value["cases"]
    _fail(type(cases) is list and 0 < len(cases) <= MAX_CASES, "CORPUS_CASE_CAP")
    identifiers: set[str] = set()
    total = 0
    for case in cases:
        _fail(type(case) is dict and set(case) == {"case_id", "path", "adapter", "sha256", "byte_count"}, "CORPUS_SCHEMA")
        identifier = case["case_id"]
        _fail(type(identifier) is str and CASE_ID.fullmatch(identifier) is not None
              and identifier not in identifiers, "CORPUS_CASE_ID")
        identifiers.add(identifier)
        _fail(type(case["adapter"]) is str and case["adapter"] in ADAPTERS, "CORPUS_ADAPTER")
        name = case["path"]
        _fail(type(name) is str and 0 < len(name) <= 1024 and "\\" not in name
              and all(ord(c) >= 32 for c in name), "CORPUS_PATH")
        path, windows = PurePosixPath(name), PureWindowsPath(name)
        _fail(not path.is_absolute() and not windows.drive and not windows.root
              and all(part not in {"", ".", ".."} for part in name.split("/"))
              and ":" not in name and path.suffix.casefold() == SUFFIXES[case["adapter"]], "CORPUS_PATH")
        _fail(_pin(case["sha256"]) and type(case["byte_count"]) is int
              and 0 <= case["byte_count"] <= MAX_INPUT_BYTES, "CORPUS_INPUT_CAP_OR_PIN")
        total += case["byte_count"]
        _fail(total <= MAX_TOTAL_BYTES, "CORPUS_TOTAL_CAP")
    return cases


def _observations(report: dict, adapter: str) -> tuple[dict, list[tuple[str, str]]]:
    # Hash container names in the combined report. Raw per-project censuses can
    # contain private object names and belong in a separate local evidence root.
    if adapter == "GXW-Q":
        counts = {"pous": report["topology"]["pou"]["observed_count"],
                  "reader_rows": report["topology"]["record"]["reader_row_count"],
                  "container_items": report["container"]["hdb_substream_count"]}
        entries = [(item["stream"], item["sha256"]) for item in report["container"]["hdb_substreams"]]
    else:
        counts = report["counts"]
        entries = [(item["entry"], item["sha256"]) for item in report["container_entries"]]
    _fail(type(counts) is dict and all(type(v) is int and v >= 0 for v in counts.values()), "CORPUS_CENSUS_SCHEMA")
    _fail(all(type(name) is str and _pin(pin) for name, pin in entries), "CORPUS_CENSUS_SCHEMA")
    return counts, [(hashlib.sha256(name.encode("utf-8")).hexdigest(), pin) for name, pin in entries]


def corpus_census(manifest: dict, source_root: Path) -> dict:
    cases = validate_manifest(manifest)
    root = _reject_link_like_ancestors(source_root, "corpus root").resolve(strict=True)
    _fail(root.is_dir(), "CORPUS_ROOT")
    results = []
    keys: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    duplicates: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        row = {key: case[key] for key in ("case_id", "adapter", "sha256", "byte_count")}
        duplicates[case["sha256"]].append(case["case_id"])
        try:
            source = root.joinpath(*PurePosixPath(case["path"]).parts)
            body, digest = _retained_bytes(source, "corpus source", MAX_INPUT_BYTES)
            _fail(digest == case["sha256"] and len(body) == case["byte_count"], "CORPUS_SOURCE_PIN_MISMATCH")
            # The adapter receives only the retained bytes, not a reopened
            # mutable original. All adapters retain their independent caps.
            with tempfile.TemporaryDirectory(prefix="gx-re-corpus-") as temporary:
                snapshot = Path(temporary) / ("source" + SUFFIXES[case["adapter"]])
                snapshot.write_bytes(body)
                observation = ADAPTERS[case["adapter"]](snapshot, digest)
            current_body, current_digest = _retained_bytes(source, "corpus source", MAX_INPUT_BYTES)
            _fail(current_digest == digest and current_body == body, "CORPUS_SOURCE_CHANGED")
            counts, entries = _observations(observation, case["adapter"])
            _fail(len(keys.keys() | {(case["adapter"], name) for name, _ in entries}) <= MAX_KEYS, "CORPUS_KEY_CAP")
            for name, pin in entries:
                keys[(case["adapter"], name)][pin].add(case["case_id"])
            row.update(decision="STRUCTURE_OBSERVED", counts=counts, input_unchanged=True)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, zipfile.BadZipFile) as error:
            # Never publish exception text: it can contain original paths or
            # object names. Keep a stable reason and every failed occurrence.
            row.update(decision="BLOCKED", reason=getattr(error, "code", "CORPUS_CENSUS_FAILED"))
        results.append(row)
    variants = [{"adapter": adapter, "container_key_sha256": name,
                 "variants": [{"content_sha256": pin, "case_ids": sorted(ids)}
                              for pin, ids in sorted(contents.items())]}
                for (adapter, name), contents in sorted(keys.items()) if len(contents) > 1]
    states = dict(Counter(row["decision"] for row in results))
    # Counts describe observations per adapter. They are not a shared semantic
    # denominator and are intentionally not combined into a support rate.
    return {"format": "plcman.gx-re-lab.corpus-census", "version": 1,
            "decision": "CORPUS_OBSERVED" if states.get("BLOCKED", 0) == 0 else "CORPUS_WITH_BLOCKS",
            "case_count": len(results), "unique_inputs": len(duplicates), "states": states,
            "adapters": dict(Counter(row["adapter"] for row in results)), "cases": results,
            "duplicate_inputs": [{"sha256": pin, "case_ids": ids} for pin, ids in sorted(duplicates.items()) if len(ids) > 1],
            "reused_container_keys": variants, "semantic_coverage": "NOT_MEASURED",
            "support_claim": "NOT_CLAIMED", "lifecycle": "NOT_RUN", "target_acceptance": "NOT_RUN"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        _fail(_pin(args.manifest_sha256), "CORPUS_MANIFEST_PIN_SCHEMA")
        raw, digest = _retained_bytes(args.manifest, "corpus manifest", 1024 * 1024)
        _fail(digest == args.manifest_sha256, "CORPUS_MANIFEST_PIN_MISMATCH")
        report = corpus_census(_json_no_duplicates(raw), args.source_root)
        report["manifest_sha256"] = digest
        report["producer_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        encoded = _publish_json(args.output, report)
        summary = {key: report[key] for key in ("decision", "case_count", "unique_inputs", "states")}
        summary["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    except (OSError, ValueError, RuntimeError) as error:
        summary = {"decision": "BLOCKED", "reason": getattr(error, "code", "CORPUS_CENSUS_FAILED")}
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["decision"] == "CORPUS_OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
