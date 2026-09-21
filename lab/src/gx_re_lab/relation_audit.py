"""Pinned research-only audit of GX3 raw storage and active POU relations."""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any
import re

from .lab import LabError, MAX_MANIFEST_BYTES, _json_no_duplicates, _retained_bytes
from gx3_core.archive import ArchiveBudget, SafeGx3Archive
import gx3_fx5_profile.topology as topology_module
import gx3_fx5_profile.detector as detector_module


FORMAT = "plcman.gx-re-lab.storage-semantic-case"
TOP_KEYS = {"format", "version", "case_id", "profile", "source", "raw_components", "active_pous", "inactive_empty_caches"}
MAX_SOURCE_BYTES = 16 * 1024 * 1024
HEX = set("0123456789abcdef")
SQL_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
RELATION_ROLES = {"link_order", "program_qpg", "step_info", "pcode", "lddb", "mildb"}
PROFILE = {"profile_id": "mitsubishi.gx3.fx5u.ladder", "decision": "SUPPORTED"}


def _fail(condition: bool, code: str = "CONTRACT_SCHEMA") -> None:
    if not condition:
        raise LabError(code)


def _fingerprint(value: object) -> dict[str, Any]:
    _fail(isinstance(value, dict) and set(value) == {"byte_count", "sha256"})
    _fail(type(value["byte_count"]) is int and value["byte_count"] >= 0)
    _fail(isinstance(value["sha256"], str) and len(value["sha256"]) == 64 and set(value["sha256"]) <= HEX)
    return value


def _path(value: object) -> str:
    _fail(isinstance(value, str) and value and not value.startswith("/") and "\\" not in value)
    _fail(all(part not in {"", ".", ".."} for part in value.split("/")))
    return value


def _pou(value: object) -> dict[str, Any]:
    keys = {"pou_id", "name", "language", "program_kind", "execution_order", "relations"}
    _fail(isinstance(value, dict) and set(value) == keys)
    _fail(isinstance(value["pou_id"], str) and value["pou_id"].isdigit())
    _fail(all(isinstance(value[key], str) for key in ("name", "language", "program_kind")))
    _fail(type(value["execution_order"]) is int and value["execution_order"] >= 0)
    _fail(isinstance(value["relations"], dict) and set(value["relations"]) == RELATION_ROLES)
    for item in value["relations"].values():
        _fail(item is None or isinstance(item, str))
        if item is not None:
            _path(item)
    return value


def _component(value: object) -> dict[str, Any]:
    keys = {"path", "byte_count", "sha256", "sqlite"}
    _fail(isinstance(value, dict) and set(value) == keys)
    _path(value["path"])
    _fingerprint({"byte_count": value["byte_count"], "sha256": value["sha256"]})
    sqlite = value["sqlite"]
    if sqlite is None:
        return value
    _fail(isinstance(sqlite, dict) and set(sqlite) == {"table", "columns", "row_count"})
    _fail(isinstance(sqlite["table"], str) and SQL_IDENTIFIER.fullmatch(sqlite["table"]) is not None)
    _fail(isinstance(sqlite["columns"], list) and sqlite["columns"] and all(isinstance(item, str) and SQL_IDENTIFIER.fullmatch(item) is not None for item in sqlite["columns"]))
    _fail(len(sqlite["columns"]) == len(set(sqlite["columns"])))
    _fail(type(sqlite["row_count"]) is int and sqlite["row_count"] >= 0)
    return value


def read_contract(path: Path, pin: str) -> dict[str, Any]:
    _fail(isinstance(pin, str) and len(pin) == 64 and set(pin.casefold()) <= HEX, "CONTRACT_PIN_SCHEMA")
    raw, digest = _retained_bytes(path, "--contract", MAX_MANIFEST_BYTES)
    if digest != pin.casefold():
        raise LabError("CONTRACT_PIN_MISMATCH")
    value = _json_no_duplicates(raw)
    _fail(set(value) == TOP_KEYS and value.get("format") == FORMAT and type(value.get("version")) is int and value["version"] == 1)
    _fail(isinstance(value["case_id"], str) and value["case_id"])
    _fail(value["profile"] == PROFILE)
    _fingerprint(value["source"])
    _fail(isinstance(value["raw_components"], list) and value["raw_components"])
    components = [_component(item) for item in value["raw_components"]]
    paths = [item["path"] for item in components]
    _fail(len(paths) == len(set(paths)))
    _fail(isinstance(value["active_pous"], list) and value["active_pous"])
    pous = [_pou(item) for item in value["active_pous"]]
    ids = [item["pou_id"] for item in pous]
    _fail(len(ids) == len(set(ids)))
    _fail(isinstance(value["inactive_empty_caches"], list))
    inactive_paths: list[str] = []
    for item in value["inactive_empty_caches"]:
        _fail(isinstance(item, dict) and set(item) == {"path", "same_stem_active_path"})
        cache, active = _path(item["path"]), _path(item["same_stem_active_path"])
        _fail(cache in paths and active in paths and cache.endswith("_MilDB.db") and active.endswith("_LDDB.db"))
        _fail(cache[:-9] == active[:-8])
        inactive_paths.append(cache)
    _fail(len(inactive_paths) == len(set(inactive_paths)))
    active_paths = {path for pou in pous for path in pou["relations"].values() if path is not None}
    _fail(not (active_paths & set(inactive_paths)), "RAW_COMPONENT_ROLE_ACCOUNTING")
    _fail(active_paths | set(inactive_paths) == set(paths), "RAW_COMPONENT_ROLE_ACCOUNTING")
    return value


def _sqlite(archive: SafeGx3Archive, component: dict[str, Any]) -> tuple[list[str], int]:
    expected = component["sqlite"]
    if expected is None:
        return [], 0
    # Archive construction already validates every .db header, integrity and foreign keys.
    _fail(any(item.entry == component["path"] for item in archive.sqlite_evidence), "RAW_COMPONENT_SQLITE")
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(archive.read(component["path"]))
        connection.execute("PRAGMA query_only = ON")
        columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{expected["table"]}")')]
        count = connection.execute(f'SELECT COUNT(*) FROM "{expected["table"]}"').fetchone()[0]
    except sqlite3.DatabaseError as error:
        raise LabError("RAW_COMPONENT_SQLITE") from error
    finally:
        connection.close()
    return columns, count


def _actual_pous(archive: SafeGx3Archive) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    topology = topology_module.discover_pous(archive)
    actual = []
    for item in topology["pous"]:
        actual.append({
            key: item[key] for key in ("pou_id", "name", "language", "program_kind", "execution_order")
        } | {"relations": dict(item["relations"])})
    return actual, topology["findings"], topology["unassigned_database_pairs"]


def audit(contract_path: Path, contract_sha256: str, source: Path) -> dict[str, Any]:
    contract = read_contract(contract_path, contract_sha256)
    body, source_hash = _retained_bytes(source, "--source", MAX_SOURCE_BYTES)
    source_fp = _fingerprint(contract["source"])
    if (len(body), source_hash) != (source_fp["byte_count"], source_fp["sha256"]):
        raise LabError("SOURCE_PIN_MISMATCH")
    budget = ArchiveBudget(max_input_bytes=MAX_SOURCE_BYTES, max_entries=2000,
                           max_entry_bytes=MAX_SOURCE_BYTES, max_total_bytes=64 * 1024 * 1024)
    with tempfile.TemporaryDirectory(prefix="gx-re-relation-") as directory:
        retained = Path(directory) / "snapshot.gx3"
        retained.write_bytes(body)
        try:
            archive_context = SafeGx3Archive(retained, budget)
        except (OSError, ValueError, sqlite3.Error, zipfile.BadZipFile) as error:
            raise LabError("ARCHIVE_INVALID") from error
        try:
            with archive_context as archive:
                observed_paths: set[str] = set()
                empty_paths: set[str] = set()
                row_counts: dict[str, int] = {}
                for component in contract["raw_components"]:
                    path = component["path"]
                    if path not in archive.entries:
                        raise LabError("RAW_COMPONENT_MISSING")
                    info = archive.entries[path]
                    if (info.file_size, archive.digest(path)) != (component["byte_count"], component["sha256"]):
                        raise LabError("RAW_COMPONENT_FINGERPRINT_MISMATCH")
                    observed_paths.add(path)
                    columns, count = _sqlite(archive, component)
                    if component["sqlite"] is not None:
                        expected = component["sqlite"]
                        if columns != expected["columns"]:
                            raise LabError("RAW_COMPONENT_SQLITE_SCHEMA")
                        if count != expected["row_count"]:
                            raise LabError("RAW_COMPONENT_ROW_COUNT")
                        row_counts[path] = count
                        if expected["table"] == "MIL" and count == 0:
                            empty_paths.add(path)
                inactive = contract["inactive_empty_caches"]
                for item in inactive:
                    if row_counts.get(item["path"]) != 0:
                        raise LabError("INACTIVE_EMPTY_CACHE_NONEMPTY")
                profile = detector_module.detect(archive)
                if (profile.profile_id != PROFILE["profile_id"] or profile.decision.value != PROFILE["decision"] or profile.findings):
                    raise LabError("PROFILE_MISMATCH")
                actual_pous, findings, unassigned = _actual_pous(archive)
                if unassigned:
                    raise LabError("UNASSIGNED_DATABASE_PAIR")
                active_paths = {path for pou in actual_pous for path in pou["relations"].values() if path is not None}
                inactive_paths = {item["path"] for item in inactive}
                if inactive_paths != empty_paths:
                    raise LabError("INACTIVE_EMPTY_CACHE_ACCOUNTING")
                for item in inactive:
                    cache, active = item["path"], item["same_stem_active_path"]
                    if cache in active_paths:
                        raise LabError("INACTIVE_EMPTY_CACHE_ACTIVE_CONFLICT")
                    if active not in active_paths:
                        raise LabError("INACTIVE_EMPTY_CACHE_STEM_NOT_ACTIVE")
                if findings or actual_pous != contract["active_pous"]:
                    raise LabError("ACTIVE_POU_RELATION_MISMATCH")
                counts = {
                    "archive_entries_observed": len(archive.entries),
                    "raw_components_observed": len(observed_paths),
                    "active_relation_paths_observed": len(active_paths),
                    "inactive_empty_caches_observed": len(empty_paths),
                }
        except LabError:
            raise
        except (OSError, ValueError, sqlite3.Error, zipfile.BadZipFile) as error:
            raise LabError("ARCHIVE_INVALID") from error
    return {
        "format": "plcman.gx-re-lab.storage-semantic-report", "version": 1,
        "case_id": contract["case_id"], "decision": "RELATION_STORAGE_MATCH",
        "lifecycle": "NOT_RUN", "source_export_comparison": "NOT_RUN",
        "active_ladder_semantic_comparison": "NOT_RUN",
        "execution": {
            "contract_sha256": contract_sha256.casefold(),
            "source": {"byte_count": len(body), "sha256": source_hash},
            "audit_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "topology_sha256": hashlib.sha256(Path(topology_module.__file__).read_bytes()).hexdigest(),
            "detector_sha256": hashlib.sha256(Path(detector_module.__file__).read_bytes()).hexdigest(),
        },
        "counts": {
            "raw_components_expected": len(contract["raw_components"]),
            **counts,
            "active_pous_expected": len(contract["active_pous"]),
            "active_relation_paths_expected": sum(sum(path is not None for path in item["relations"].values()) for item in contract["active_pous"]),
            "inactive_empty_caches_expected": len(contract["inactive_empty_caches"]),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.contract, args.contract_sha256, args.source)
    except LabError as error:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": [error.code]}
    except Exception:
        report = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "blockers": ["RELATION_AUDIT_BLOCKED"]}
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["decision"] == "RELATION_STORAGE_MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
