"""Build and semantically validate Neutral IR 1.0.0."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from gx3_core import SafeGx3Archive
from gx3_fx5_profile import detect, discover_pous, discover_project
from gx3_fx5_profile.decoder import (
    bind_local_label_programs,
    decode_comments,
    decode_labels,
    decode_records,
)

PACKAGE = "gx3-fx5-parser-toolkit"
VERSION = "0.4.0"


def _source_commit() -> str:
    """Return artifact-only provenance; never inspect ancestor Git."""
    try:
        from importlib import resources
        value = json.loads((resources.files(__package__) / '_provenance.json').read_text(encoding='utf-8'))
        source_commit = value.get('source_commit')
        return source_commit if isinstance(source_commit, str) and re.fullmatch(r'[0-9a-f]{40}', source_commit) else '0000000000000000000000000000000000000000'
    except (FileNotFoundError, json.JSONDecodeError, ModuleNotFoundError):
        return '0000000000000000000000000000000000000000'

def _finding(
    kind: str, scope: str, locator: str, digest: str, reason: str,
    finding_code: str = "MINING_REQUIRED",
) -> dict[str, str]:
    allowed = {
        "profile",
        "topology",
        "record",
        "opcode",
        "operand",
        "comment",
        "label",
        "parameter",
    }
    return {
        "finding_code": finding_code,
        "scope": scope,
        "object_kind": kind if kind in allowed else "topology",
        "locator": locator or "GX3",
        "digest": digest or hashlib.sha256((locator or reason).encode()).hexdigest(),
        "reason": reason,
    }


def build_neutral_ir(source: Path) -> dict[str, Any]:
    with SafeGx3Archive(source) as archive:
        profile = detect(archive)
        project = discover_project(archive)
        supported = profile.decision.value == "SUPPORTED"
        topology = (
            discover_pous(archive)
            if supported
            else {"pous": [], "findings": [], "unassigned_database_pairs": []}
        )
        global_findings = [
            _finding(
                item.get("object_kind", "topology"),
                item.get("scope", "project"),
                item.get("locator", "GX3"),
                item.get("digest", ""),
                item.get("reason", "unresolved topology"),
                item.get("disposition", "MINING_REQUIRED"),
            )
            for item in [*profile.to_dict()["findings"], *topology["findings"]]
        ]
        pous: list[dict[str, Any]] = []
        record_coverage = {"total": 0, "decoded": 0, "partial": 0, "unknown": 0}
        for index, item in enumerate(topology["pous"]):
            records, findings, coverage = decode_records(archive, item)
            for key in record_coverage:
                record_coverage[key] += coverage[key]
            name = (
                item["name"]
                or f"UNRESOLVED_{hashlib.sha256(item['pou_id'].encode()).hexdigest()[:12]}"
            )
            if item["name"] is None:
                findings.append(
                    _finding(
                        "topology",
                        f"pou:{item['pou_id']}",
                        "Program.qpg",
                        hashlib.sha256(item["pou_id"].encode()).hexdigest(),
                        "POU name relation is unresolved; stable placeholder emitted",
                    )
                )
            pous.append(
                {
                    "pou_id": item["pou_id"],
                    "name": name,
                    "language": item["language"],
                    "execution_order": item["execution_order"]
                    if item["execution_order"] is not None
                    else index,
                    "program_kind": item["program_kind"],
                    "relations": [
                        value for value in item["relations"].values() if value
                    ],
                    "records": records,
                    "findings": sorted(
                        findings,
                        key=lambda value: (
                            value["scope"],
                            value["object_kind"],
                            value["locator"],
                            value["digest"],
                        ),
                    ),
                }
            )
        comments, comment_findings, comment_coverage = (
            decode_comments(archive)
            if supported
            else ([], [], {"total": 0, "decoded": 0, "partial": 0, "unknown": 0})
        )
        labels, label_findings, label_coverage = (
            decode_labels(archive)
            if supported
            else ([], [], {"total": 0, "decoded": 0, "partial": 0, "unknown": 0})
        )
        if supported:
            labels, label_findings, label_coverage = bind_local_label_programs(
                labels, label_findings, label_coverage, pous
            )
        global_findings.extend(comment_findings)
        global_findings.extend(label_findings)
        config_digest = project["provenance"]["source_digest"]
        config_provenance = {
            "source_entry": project["provenance"]["source_entry"],
            "source_store": "XML",
            "source_locator": project["provenance"]["source_locator"],
            "source_digest": config_digest,
            "relation_evidence": [project["provenance"]["relation_evidence"]],
        }
        result = {
            "schema_name": "plcman.gx3.neutral-ir",
            "schema_version": "1.0.0",
            "producer": {
                "package": PACKAGE,
                "version": VERSION,
                "source_commit": _source_commit(),
            },
            "input": {
                "display_id": archive.sha256[:16],
                "byte_count": archive.byte_count,
                "sha256": archive.sha256,
                "read_only_unchanged": True,
            },
            "profile": {
                "profile_id": profile.profile_id,
                "contract_version": "1.0.0",
                "family": "FX5",
                "cpu_ui_selection": project["cpu"],
                "language": "Ladder",
                "detector_status": profile.decision.value,
                "evidence": [config_provenance],
            },
            "project": {
                "project_id": project["title_digest"],
                "provenance": config_provenance,
            },
            "pous": sorted(
                pous, key=lambda value: (value["execution_order"], value["pou_id"])
            ),
            "comments": sorted(
                comments,
                key=lambda value: (
                    value["scope"],
                    value["device_id"],
                    value["language_slot"],
                    value["provenance"]["source_locator"],
                ),
            ),
            "labels": sorted(
                labels,
                key=lambda value: (
                    value["scope"],
                    value["label_id"],
                    value["language_slot"],
                    value["provenance"]["source_locator"],
                ),
            ),
            "findings": sorted(
                global_findings,
                key=lambda value: (
                    value["scope"],
                    value["object_kind"],
                    value["locator"],
                    value["digest"],
                ),
            ),
            "coverage": {
                "project": {
                    "total": 1,
                    "decoded": int(profile.decision.value == "SUPPORTED"),
                    "partial": int(profile.decision.value == "AMBIGUOUS"),
                    "unknown": int(profile.decision.value == "UNSUPPORTED"),
                },
                "pou": {
                    "total": len(pous),
                    "decoded": sum(not item["findings"] for item in pous),
                    "partial": sum(bool(item["findings"]) for item in pous),
                    "unknown": 0,
                },
                "record": record_coverage,
                "comment": comment_coverage,
                "label": label_coverage,
            },
        }
    validate_ir(result)
    return result


def validate_ir(value: dict[str, Any]) -> None:
    producer = value.get("producer") if isinstance(value, dict) else None
    profile = value.get("profile") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or not isinstance(producer, dict)
        or not isinstance(profile, dict)
        or value.get("schema_name") != "plcman.gx3.neutral-ir"
        or value.get("schema_version") != "1.0.0"
        or producer.get("package") != PACKAGE
        or profile.get("profile_id") != "mitsubishi.gx3.fx5u.ladder"
        or profile.get("family") != "FX5"
    ):
        raise ValueError("FX5 Neutral IR package/profile identity mismatch")
    for kind, counts in value["coverage"].items():
        if counts["total"] != counts["decoded"] + counts["partial"] + counts["unknown"]:
            raise ValueError(f"coverage conservation failed: {kind}")
    pou_ids = [item["pou_id"] for item in value["pous"]]
    if len(pou_ids) != len(set(pou_ids)):
        raise ValueError("duplicate POU identifier")
    for pou in value["pous"]:
        record_ids = [item["record_id"] for item in pou["records"]]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError(f"duplicate record identifier: {pou['pou_id']}")
        known = set(record_ids)
        for record in pou["records"]:
            target = record["continues_record_id"]
            if target is not None and target not in known:
                raise ValueError("continuation target is missing")
    json.dumps(value, ensure_ascii=False, sort_keys=True)
