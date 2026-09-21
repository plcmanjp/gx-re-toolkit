"""Bounded R04CPU structural census through the public R-series parser.

The R-series parser performs its normal IR decode.  This research-only adapter
publishes only structural observations plus the parser's separately labelled
IR coverage; it does not equate a decode count with structural observation,
profile support, lifecycle, or target acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
import tempfile
import zipfile
from typing import Any

import gx3_r_parser_toolkit.archive as r04_archive  # noqa: E402
import gx3_r_parser_toolkit.parser as r04_parser  # noqa: E402

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2_000
MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000
MAX_REPORT_BYTES = 4 * 1024 * 1024
HEX = set("0123456789abcdef")


class CensusError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fail(condition: bool, code: str) -> None:
    if not condition:
        raise CensusError(code)


def _link_like(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


def _regular_file(path: Path, cap: int, code: str) -> Path:
    absolute = Path(path).absolute()
    _fail(not any(_link_like(item) for item in (absolute, *absolute.parents)), "LINK_LIKE_INPUT")
    _fail(absolute.is_file() and not absolute.is_symlink(), code)
    _fail(absolute.stat().st_size <= cap, code)
    return absolute.resolve(strict=True)


def _read_retained(path: Path, pin: str) -> tuple[bytes, str]:
    _fail(isinstance(pin, str) and len(pin) == 64 and set(pin) <= HEX, "SOURCE_PIN_SCHEMA")
    source = _regular_file(path, MAX_INPUT_BYTES, "INPUT_CAP_OR_TYPE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        _fail(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_INPUT_BYTES, "INPUT_CAP_OR_TYPE")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_INPUT_BYTES:
            block = os.read(descriptor, min(1024 * 1024, MAX_INPUT_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            chunks.append(block)
        _fail(total <= MAX_INPUT_BYTES, "INPUT_CAP_OR_TYPE")
        body = b"".join(chunks)
        after = os.fstat(descriptor)
        _fail((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "SOURCE_CHANGED")
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(body).hexdigest()
    _fail(digest == pin, "SOURCE_PIN_MISMATCH")
    return body, digest


def _safe_zip_name(name: str) -> bool:
    posix, windows = PurePosixPath(name), PureWindowsPath(name)
    return bool(name and len(name) <= 1024 and len(posix.parts) <= 32 and
                not posix.is_absolute() and not windows.is_absolute() and not windows.drive and
                all(part not in {"", ".", ".."} for part in posix.parts) and
                all(ord(char) >= 32 for char in name))


def _zip_link(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK


def _preflight_zip(path: Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            _fail(0 < len(infos) <= MAX_ARCHIVE_ENTRIES, "ARCHIVE_ENTRY_CAP")
            total = 0
            names: set[str] = set()
            records: list[dict[str, Any]] = []
            for info in sorted(infos, key=lambda item: item.filename):
                _fail(_safe_zip_name(info.filename), "ARCHIVE_PATH")
                _fail(info.filename.casefold() not in names, "ARCHIVE_DUPLICATE")
                names.add(info.filename.casefold())
                if info.is_dir():
                    _fail(info.file_size == 0, "ARCHIVE_DIRECTORY")
                    continue
                _fail(not _zip_link(info) and info.file_size <= MAX_ENTRY_BYTES, "ARCHIVE_ENTRY_CAP")
                _fail(info.file_size / max(info.compress_size, 1) <= MAX_COMPRESSION_RATIO, "ARCHIVE_RATIO")
                total += info.file_size
                _fail(total <= MAX_TOTAL_BYTES, "ARCHIVE_TOTAL_CAP")
                records.append({"entry": info.filename, "byte_count": info.file_size,
                                "compressed_bytes": info.compress_size,
                                "compression": info.compress_type})
    except zipfile.BadZipFile as error:
        raise CensusError("ARCHIVE_INVALID") from error
    return {"archive_entry_count": len(infos),
            "directory_entry_count": sum(info.is_dir() for info in infos),
            "file_entries": records}


def _producer_hashes() -> dict[str, str]:
    return {
        "r04_census.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "gx3_r_parser_toolkit.archive": hashlib.sha256(Path(r04_archive.__file__).read_bytes()).hexdigest(),
        "gx3_r_parser_toolkit.parser": hashlib.sha256(Path(r04_parser.__file__).read_bytes()).hexdigest(),
    }


def _coverage(value: object) -> dict[str, dict[str, int]]:
    _fail(isinstance(value, dict), "P003_IR_SCHEMA")
    result: dict[str, dict[str, int]] = {}
    for layer, count in value.items():
        _fail(isinstance(layer, str) and isinstance(count, dict), "P003_IR_SCHEMA")
        keys = {"total", "decoded", "partial", "unknown"}
        _fail(set(count) == keys and all(type(count[key]) is int and count[key] >= 0 for key in keys), "P003_IR_SCHEMA")
        _fail(count["decoded"] + count["partial"] + count["unknown"] == count["total"], "P003_IR_SCHEMA")
        result[layer] = {key: count[key] for key in sorted(keys)}
    return result


def census(source: Path, source_sha256: str) -> dict[str, Any]:
    body, digest = _read_retained(Path(source), source_sha256)
    producer_before = _producer_hashes()
    with tempfile.TemporaryDirectory(prefix="gx-re-r04-census-") as directory:
        retained = Path(directory) / "snapshot.gx3"
        retained.write_bytes(body)
        container_observation = _preflight_zip(retained)
        entries = container_observation["file_entries"]
        # R-series validates the retained file again. Its default limits are wider,
        # so the preflight above remains the binding inflation budget.
        ir = r04_parser.parse(retained)
        _fail(ir.get("status") != "FATAL", "P003_FATAL")
        r04_parser.validate_ir(ir)
    _fail(_producer_hashes() == producer_before, "PRODUCER_IDENTITY_DRIFT")
    _, final_digest = _read_retained(Path(source), source_sha256)
    _fail(final_digest == digest, "SOURCE_CHANGED")
    profile = ir.get("profile")
    pous = ir.get("pous")
    findings = ir.get("findings")
    parser_producer = ir.get("producer")
    _fail(isinstance(profile, dict) and isinstance(pous, list) and isinstance(findings, list) and isinstance(parser_producer, dict), "P003_IR_SCHEMA")
    parser_commit = parser_producer.get("source_commit")
    _fail(isinstance(parser_commit, str) and len(parser_commit) == 40 and set(parser_commit) <= HEX, "P003_IR_SCHEMA")
    profile_status = profile.get("detector_status")
    _fail(profile_status in {"SUPPORTED", "UNSUPPORTED", "AMBIGUOUS"}, "P003_IR_SCHEMA")
    sqlite_entries = []
    for item in entries:
        if item["entry"].casefold().endswith(".db"):
            sqlite_entries.append(item["entry"])
    return {
        "format": "plcman.gx-re-lab.r04-census",
        "version": 1,
        "decision": "STRUCTURE_OBSERVED",
        "support_claim": "NOT_CLAIMED",
        "lifecycle": "NOT_RUN",
        "input": {"sha256": digest, "byte_count": len(body), "read_only_unchanged": True},
        "producer": {"adapter_tool_sha256": producer_before["r04_census.py"],
                     "producer_files_sha256": producer_before, "p003_source_commit": parser_commit,
                     "p003_parse_executed": True, "p003_parse_scope": "full_ir_decode_not_published_as_structural_acceptance"},
        "profile": {"profile_id": profile.get("profile_id"), "detector_status": profile_status,
                    "cpu_ui_selection": profile.get("cpu_ui_selection"), "language": profile.get("language"),
                    "evidence": profile.get("evidence")},
        "container": {"archive_entry_count": container_observation["archive_entry_count"],
                      "directory_entry_count": container_observation["directory_entry_count"],
                      "file_entry_count": len(entries), "sqlite_entry_count": len(sqlite_entries),
                      "entries": entries},
        "topology": {"pou_count": len(pous),
                     "pous": [{key: item.get(key) for key in ("pou_id", "order", "program_container", "name", "stepinfo", "pcode")} for item in pous],
                     "findings": findings},
        "ir_coverage": _coverage(ir.get("coverage")),
        "decoded_field_coverage": {"denominator": None, "decoded": None, "partial": None, "unknown": None,
                                   "reason": "NOT_MEASURED: census does not claim field-level decode coverage; P003 IR coverage is reported separately"},
        "unknown_byte_ranges": {"status": "NOT_MEASURED", "ranges": None},
        "target_acceptance": "NOT_RUN",
    }


def _output_parent(path: Path) -> Path:
    target = Path(path).absolute()
    _fail(not target.exists(), "OUTPUT_NOT_NEW")
    parent = target.parent
    _fail(parent.is_dir() and not any(_link_like(item) for item in (parent, *parent.parents)), "OUTPUT_PARENT")
    return target


def _publish_json(path: Path, value: dict[str, Any]) -> bytes:
    target = _output_parent(path)
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _fail(len(encoded) <= MAX_REPORT_BYTES, "REPORT_CAP")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".r04-census-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError as error:
            raise CensusError("OUTPUT_NOT_NEW") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return encoded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = census(args.source, args.source_sha256)
        encoded = _publish_json(args.output, report)
        summary = {"decision": report["decision"], "lifecycle": report["lifecycle"], "input": report["input"],
                   "profile_status": report["profile"]["detector_status"], "report_sha256": hashlib.sha256(encoded).hexdigest()}
    except (CensusError, OSError, ValueError, zipfile.BadZipFile) as error:
        summary = {"decision": "BLOCKED", "lifecycle": "NOT_RUN", "reason": error.code if isinstance(error, CensusError) else "R04_CENSUS_FAILED"}
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["decision"] == "STRUCTURE_OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
