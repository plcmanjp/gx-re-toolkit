"""Pinned, local-only structural census using the existing FX5 FX5 reader."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

from .lab import LabError, _retained_bytes
import gx3_core.archive as archive_module
import gx3_fx5_profile.detector as detector_module
import gx3_fx5_profile.topology as topology_module
from gx3_core.archive import ArchiveBudget, SafeGx3Archive
from gx3_fx5_parser_toolkit.cli import _publish_json

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024


def census(source: Path, source_sha256: str) -> dict:
    if (type(source_sha256) is not str or len(source_sha256) != 64
            or any(c not in "0123456789abcdef" for c in source_sha256)):
        raise LabError("SOURCE_PIN_SCHEMA")
    body, digest = _retained_bytes(source, "census source", MAX_INPUT_BYTES)
    if digest != source_sha256:
        raise LabError("SOURCE_PIN_MISMATCH")
    budget = ArchiveBudget(max_input_bytes=MAX_INPUT_BYTES, max_entries=2000,
                           max_entry_bytes=16 * 1024 * 1024, max_total_bytes=64 * 1024 * 1024)
    # The FX5 reader receives only this retained snapshot. It cannot reopen a
    # replaced original path or claim its current contents are unchanged.
    with tempfile.TemporaryDirectory(prefix="gx-re-census-") as directory:
        retained = Path(directory) / "snapshot.gx3"
        retained.write_bytes(body)
        with SafeGx3Archive(retained, budget) as archive:
            profile = detector_module.detect(archive)
            if profile.decision.value != "SUPPORTED":
                raise LabError("PROFILE_NOT_CONFIRMED")
            topology = topology_module.discover_pous(archive)
            entries = [{"entry": name, "byte_count": info.file_size,
                        "compressed_bytes": info.compress_size, "compression": info.compress_type,
                        "sha256": archive.digest(name)} for name, info in sorted(archive.entries.items())]
            databases = [asdict(item) for item in archive.sqlite_evidence]
            counts = {"archive_entries": archive.archive_entry_count, "files": len(entries),
                      "sqlite_databases": len(databases), "sqlite_tables": sum(x["table_count"] for x in databases),
                      "pous": len(topology["pous"]),
                      "unassigned_database_pairs": len(topology["unassigned_database_pairs"]),
                      "topology_findings": len(topology["findings"])}
    producer = {name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                for name, module in (("gx3_core.archive", archive_module),
                                     ("gx3_fx5_profile.detector", detector_module),
                                     ("gx3_fx5_profile.topology", topology_module))}
    return {"format": "plcman.gx-re-lab.census", "version": 1,
            "decision": "STRUCTURE_OBSERVED", "lifecycle": "NOT_RUN",
            "input": {"sha256": digest, "byte_count": len(body)}, "producer": producer,
            "counts": counts, "container_entries": entries, "sqlite": databases,
            "profile_evidence": profile.to_dict(), "topology": topology,
            "unknown_byte_ranges": {"status": "NOT_MEASURED", "ranges": None},
            "semantic_coverage": "NOT_MEASURED", "target_acceptance": "NOT_RUN"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path, help="new local report; may contain private object names")
    args = parser.parse_args(argv)
    try:
        if args.output.exists() or not args.output.parent.is_dir():
            raise LabError("OUTPUT_NOT_NEW")
        report = census(args.source, args.source_sha256)
        encoded = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(encoded) > MAX_REPORT_BYTES:
            raise LabError("REPORT_CAP")
        _publish_json(args.output, report, args.source)
        summary = {key: report[key] for key in ("format", "version", "decision", "lifecycle", "input", "counts")}
        summary["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    except (LabError, OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        summary = {"decision": "BLOCKED", "lifecycle": "NOT_RUN",
                   "reason": error.code if isinstance(error, LabError) else "CENSUS_FAILED"}
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["decision"] == "STRUCTURE_OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
