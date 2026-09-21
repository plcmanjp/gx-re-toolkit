"""Read-only Phase 1 inspection CLI."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path
from typing import Any

from gx3_core import Finding, SafeGx3Archive
from gx3_fx5_profile import detect, discover_pous, discover_project

from .acceptance import evaluate_acceptance, evaluate_evidence_manifest
from .ir import build_neutral_ir
from .projections import projection_files, publish_directory


def inspect(source: Path, summary: bool = False) -> dict[str, Any]:
    with SafeGx3Archive(source) as archive:
        profile = detect(archive)
        inspection_findings: list[Finding] = []
        topology: dict[str, Any] = {
            "pous": [],
            "unassigned_database_pairs": [],
            "findings": [],
        }
        project = None
        if profile.decision.value != "UNSUPPORTED":
            try:
                topology = discover_pous(archive)
            except (KeyError, UnicodeError, ValueError) as error:
                inspection_findings.append(
                    Finding(
                        "GX3_TOPOLOGY_DISCOVERY_FAILED",
                        "project",
                        "topology",
                        "GX3",
                        archive.sha256,
                        f"structural discovery failed: {type(error).__name__}",
                    )
                )
            try:
                project = discover_project(archive)
            except (KeyError, UnicodeError, ValueError) as error:
                inspection_findings.append(
                    Finding(
                        "GX3_PROJECT_DISCOVERY_FAILED",
                        "project",
                        "identity",
                        "Config.xml",
                        "",
                        f"project discovery failed: {type(error).__name__}",
                    )
                )
        result: dict[str, Any] = {
            "format": "plcman.gx3.phase1-inspection",
            "version": "1.0.0",
            "input": {
                "byte_count": archive.byte_count,
                "sha256": archive.sha256,
                "unchanged": True,
            },
            "archive": {
                "entry_count": archive.archive_entry_count,
                "file_count": len(archive.entries),
                "sqlite_count": len(archive.sqlite_evidence),
            },
            "profile": profile.to_dict(),
            "project": project,
            "topology": topology,
            "findings": [finding.to_dict() for finding in inspection_findings],
        }
    if summary:
        return {
            "format": result["format"],
            "version": result["version"],
            "input": result["input"],
            "archive": result["archive"],
            "profile": {
                "profile_id": result["profile"]["profile_id"],
                "decision": result["profile"]["decision"],
                "evidence": result["profile"]["evidence"],
                "finding_count": len(result["profile"]["findings"]),
            },
            "topology": {
                "pou_count": len(result["topology"]["pous"]),
                "named_pou_count": sum(
                    item["name"] is not None for item in result["topology"]["pous"]
                ),
                "assigned_database_pair_count": sum(
                    item["relations"]["lddb"] is not None
                    for item in result["topology"]["pous"]
                ),
                "finding_count": len(result["topology"]["findings"]),
            },
            "inspection_finding_count": len(result["findings"]),
        }
    return result


def _publish_json(path: Path, value: dict[str, Any], source: Path) -> None:
    target = path.resolve()
    if target == source.resolve():
        raise ValueError("output must not replace the GX3 input")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    data = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target)
    except FileExistsError as error:
        raise ValueError(
            "output already exists; no-clobber policy blocked publication"
        ) from error
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safely inspect an FX5U GX3 archive without modifying it"
    )
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument(
        "--output",
        type=Path,
        help="new JSON path; existing paths are never overwritten",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="omit customer identifiers and internal entry paths",
    )
    parser.add_argument(
        "--phase2-output",
        type=Path,
        help="new directory for Neutral IR, text, CSV, devmap and coverage projections",
    )
    parser.add_argument(
        "--phase2-acceptance",
        type=Path,
        help=(
            "new JSON path for Phase 2 readiness report; existing paths are "
            "never overwritten; does not compare official export or close Phase 2"
        ),
    )
    parser.add_argument(
        "--phase2-evidence-manifest",
        type=Path,
        help=(
            "Phase 2 evidence manifest; with --phase2-acceptance this is the only "
            "mode that can evaluate Phase 2 closure"
        ),
    )
    args = parser.parse_args(argv)
    if args.source is None and args.phase2_evidence_manifest is None:
        parser.error("source is required unless --phase2-evidence-manifest is supplied")
    if args.source is not None and args.phase2_evidence_manifest is not None:
        parser.error("source cannot be combined with --phase2-evidence-manifest")
    if args.phase2_evidence_manifest is not None and args.phase2_acceptance is None:
        parser.error("--phase2-evidence-manifest requires --phase2-acceptance")
    if args.phase2_output and (args.output or args.summary or args.phase2_acceptance):
        parser.error(
            "--phase2-output cannot be combined with --output, --summary or "
            "--phase2-acceptance"
        )
    if args.phase2_acceptance and (args.output or args.summary):
        parser.error("--phase2-acceptance cannot be combined with --output or --summary")
    if args.phase2_evidence_manifest:
        _publish_json(
            args.phase2_acceptance,
            evaluate_evidence_manifest(args.phase2_evidence_manifest),
            args.phase2_evidence_manifest,
        )
        return 0
    if args.phase2_output:
        value = build_neutral_ir(args.source)
        publish_directory(args.phase2_output, projection_files(value))
        return 0
    if args.phase2_acceptance:
        _publish_json(
            args.phase2_acceptance, evaluate_acceptance(args.source), args.source
        )
        return 0
    result = inspect(args.source, args.summary)
    if args.output:
        _publish_json(args.output, result, args.source)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
