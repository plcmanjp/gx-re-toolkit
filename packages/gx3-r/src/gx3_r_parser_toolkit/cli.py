from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
import tempfile

from .archive import sha256_file
from .parser import parse, validate_ir


_SUMMARY_COVERAGE_KINDS = ("project", "pou", "record", "comment", "label")
_SUMMARY_COVERAGE_COUNTS = ("total", "decoded", "partial", "unknown")


def _reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.stat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _summary_status(result: dict) -> str:
    if result.get("status") == "FATAL":
        return "FATAL"
    coverage = result["coverage"]
    incomplete = any(
        coverage[kind]["partial"] or coverage[kind]["unknown"]
        for kind in _SUMMARY_COVERAGE_KINDS
    )
    return "PARTIAL" if result["findings"] or incomplete else "FULL"


def _summary_coverage(result: dict) -> dict[str, dict[str, int]] | None:
    coverage = result.get("coverage")
    if coverage is None:
        return None
    return {
        kind: {count: coverage[kind][count] for count in _SUMMARY_COVERAGE_COUNTS}
        for kind in _SUMMARY_COVERAGE_KINDS
    }


def _summary(result: dict) -> dict:
    """Return the fixed public summary projection without project content."""
    profile = result.get("profile")
    return {
        "status": _summary_status(result),
        "support_status": profile["detector_status"] if profile else None,
        "coverage": _summary_coverage(result),
        "finding_count": len(result["findings"]),
    }


def publish_directory(target: Path, result: dict, source: Path | None = None) -> None:
    if result.get("status") == "FATAL":
        raise ValueError("fatal result cannot be published")
    validate_ir(result)
    if source is None:
        raise ValueError("source is required for publish")
    if any(str(item.get("reason", "")).startswith("FATAL:") for item in result["findings"]):
        raise ValueError("fatal result cannot be published")
    if target.exists() or _reparse(target.parent) or any(_reparse(parent) for parent in target.parent.absolute().parents): raise ValueError("no-clobber output already exists or parent is reparse")
    target.parent.mkdir(parents=True, exist_ok=True)
    incomplete = any(count["partial"] or count["unknown"] for count in result["coverage"].values())
    report = {"status": "PARTIAL" if result["findings"] or incomplete else "FULL", "input_sha256": result.get("input", {}).get("sha256", ""), "finding_count": len(result["findings"])}
    files = {"neutral-ir.json": canonical_json(result), "report.json": canonical_json(report), "coverage.json": canonical_json(result["coverage"]), "findings.json": canonical_json(result["findings"]), "records.txt": _records_text(result).encode("utf-8"), "comments.csv": _object_csv(result.get("comments", []), "device_id").encode("utf-8"), "labels.csv": _object_csv(result.get("labels", []), "label_id").encode("utf-8"), "devmap.csv": _devmap_csv(result).encode("utf-8")}
    for pou in result["pous"]:
        files[f"pou-{pou['pou_id']}.csv"] = _pou_csv(pou).encode("utf-8")
    try:
        with tempfile.TemporaryDirectory(dir=target.parent, prefix=".gx3-r04-") as work:
            root = Path(work)
            for name, payload in files.items():
                path = root / name; path.write_bytes(payload)
                with path.open("r+b") as handle: os.fsync(handle.fileno())
            if source is not None and sha256_file(source) != result.get("input", {}).get("sha256"):
                raise ValueError("input SHA-256 changed before publish")
            if target.exists():
                raise ValueError("no-clobber output already exists")
            os.rename(root, target)
    except FileExistsError as error:
        raise ValueError("no-clobber output already exists") from error


def _records_text(result: dict) -> str:
    rows = []
    for pou in result["pous"]:
        for record in pou["records"]:
            step = "" if record["step"] is None else str(record["step"])
            rows.append(f"{pou['pou_id']}\t{step}\t{record['opcode'] or ''}\t" + ",".join(item["raw_token"] for item in record["operands"]))
    return "\n".join(rows) + ("\n" if rows else "")


def _csv(rows: tuple[tuple[str, ...], ...]) -> str:
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    return output.getvalue()


def _pou_csv(pou: dict) -> str:
    rows = [("pou_id", "step", "kind", "opcode", "operands", "status", "continues_record_id")]
    for record in pou["records"]:
        rows.append((pou["pou_id"], "" if record["step"] is None else str(record["step"]), record["kind"], record["opcode"] or "", ",".join(item["raw_token"] for item in record["operands"]), record["status"], record.get("continues_record_id", "")))
    return _csv(tuple(rows))


def _object_csv(items: list[dict], identifier: str) -> str:
    rows = [("scope", "program_id", identifier, "language_slot", "value_state", "value")]
    for item in items:
        rows.append((item["scope"], item["program_id"] or "", item[identifier], item["language_slot"], item["value_state"], item["value"] or ""))
    return _csv(tuple(rows))


def _devmap_csv(result: dict) -> str:
    uses: dict[str, set[str]] = {}
    for pou in result["pous"]:
        for record in pou["records"]:
            for operand in record["operands"]:
                uses.setdefault(operand["raw_token"], set()).add(pou["pou_id"])
    return _csv(tuple([("device_or_literal", "pou_ids")] + [(key, ",".join(sorted(value))) for key, value in sorted(uses.items())]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only GX3 R04CPU parser")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    result = parse(args.input)
    if args.output:
        try: publish_directory(args.output, result, args.input)
        except ValueError as error: parser.error(str(error))
    print(canonical_json(_summary(result) if args.summary else result).decode("ascii"), end="")
    return 3 if any(item["reason"].startswith("FATAL:") for item in result["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
