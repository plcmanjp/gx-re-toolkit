"""Bounded, research-only GX Works2 CFB structural census through the GXW reader.

Input schema: a new, regular, pinned .gxw CFB file of at most 16 MiB.
Output schema: a new JSON report containing CFB/_hdb observations and separately
labelled reader observations.  It does not grant source authority, semantic
coverage, production support, lifecycle completion, or target acceptance.
Dependency: the existing GXW public ``gxw_ladder_reader`` only.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_SUBSTREAMS = 2_048
MAX_SUBSTREAM_BYTES = 8 * 1024 * 1024
MAX_SUBSTREAM_TOTAL_BYTES = 16 * 1024 * 1024
MAX_POU_COUNT = 1_024
MAX_RECORD_ROWS = 1_000_000
MAX_REPORT_BYTES = 4 * 1024 * 1024
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
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
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
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


def _cfb_header(body: bytes) -> dict[str, int]:
    _fail(len(body) >= 1024 and len(body) % 512 == 0 and body[:8] == CFB_MAGIC, "CFB_INVALID")
    # These fixed CFB v3 fields bound the layout before the GXW reader opens it.
    _fail(body[8:24] == b"\0" * 16 and body[26:28] == b"\x03\0" and
          body[28:30] == b"\xfe\xff" and body[30:32] == b"\x09\0" and
          body[32:34] == b"\x06\0" and body[40:44] == b"\0" * 4, "CFB_INVALID")
    return {"sector_size": 512, "sector_count": len(body) // 512 - 1}


def _load_reader() -> Any:
    import gxw_ladder_reader as module
    location = Path(module.__file__)
    _fail(location.is_file() and not _link_like(location), "P004_READER_UNAVAILABLE")
    for name in ("load_all_substreams", "collect_pous", "pou_rows"):
        _fail(callable(getattr(module, name, None)), "P004_READER_API")
    return module


reader = _load_reader()


def _producer_hashes() -> dict[str, str]:
    return {
        "gxw_census.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "gxw_ladder_reader.py": hashlib.sha256(Path(reader.__file__).read_bytes()).hexdigest(),
    }


def _write_snapshot(path: Path, body: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())


def _stream_observation(streams: object) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    _fail(isinstance(streams, dict) and 0 < len(streams) <= MAX_SUBSTREAMS, "P004_STREAM_SCHEMA")
    result: list[dict[str, Any]] = []
    retained: dict[str, bytes] = {}
    total = 0
    for name, payload in streams.items():
        _fail(isinstance(name, str) and 0 < len(name) <= 512 and all(ord(char) >= 32 for char in name), "P004_STREAM_SCHEMA")
        _fail(isinstance(payload, bytes) and len(payload) <= MAX_SUBSTREAM_BYTES, "P004_STREAM_CAP")
        total += len(payload)
        _fail(total <= MAX_SUBSTREAM_TOTAL_BYTES, "P004_STREAM_TOTAL_CAP")
        retained[name] = payload
        result.append({"stream": name, "byte_count": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    result.sort(key=lambda item: item["stream"])
    return result, retained


def _reader_observation(streams: dict[str, bytes]) -> dict[str, Any]:
    pous, comments, registry = reader.collect_pous(streams)
    _fail(isinstance(pous, dict) and len(pous) <= MAX_POU_COUNT and isinstance(comments, dict), "P004_POU_SCHEMA")
    pou_names: list[str] = []
    total_rows = 0
    unknown_instructions: set[str] = set()
    unknown_devices: set[str] = set()
    main_rows: int | None = None
    for name, value in pous.items():
        _fail(isinstance(name, str) and 0 < len(name) <= 64 and isinstance(value, tuple) and len(value) == 3 and isinstance(value[1], bytes), "P004_POU_SCHEMA")
        rows, unknown_i, unknown_d = reader.pou_rows(value[1], comments)
        _fail(isinstance(rows, list) and isinstance(unknown_i, set) and isinstance(unknown_d, set), "P004_POU_SCHEMA")
        total_rows += len(rows)
        _fail(total_rows <= MAX_RECORD_ROWS, "P004_RECORD_CAP")
        _fail(all(isinstance(token, str) and len(token) <= 512 for token in unknown_i | unknown_d), "P004_POU_SCHEMA")
        unknown_instructions.update(unknown_i)
        unknown_devices.update(unknown_d)
        if name == "MAIN":
            main_rows = len(rows)
        pou_names.append(name)
    pou_names.sort()
    return {
        "main": {"status": "OBSERVED" if "MAIN" in pous else "NOT_OBSERVED", "reader_row_count": main_rows},
        "pou": {"observed_count": len(pou_names), "names": pou_names},
        "record": {"reader_row_count": total_rows},
        "unknown_evidence": {
            "instruction_tokens": sorted(unknown_instructions),
            "device_tokens": sorted(unknown_devices),
            "registry_observed": registry is not None,
        },
    }


def _unmeasured_coverage(observed: int, reason: str) -> dict[str, Any]:
    return {"denominator": None, "observed_reader_count": observed, "decoded": None,
            "partial": None, "unknown": None, "reason": reason}


def census(source: Path, source_sha256: str) -> dict[str, Any]:
    body, digest = _read_retained(Path(source), source_sha256)
    header = _cfb_header(body)
    producer_before = _producer_hashes()
    with tempfile.TemporaryDirectory(prefix="gx-re-gxw-census-") as directory:
        retained = Path(directory) / "snapshot.gxw"
        _write_snapshot(retained, body)
        try:
            stream_records, streams = _stream_observation(reader.load_all_substreams(str(retained)))
            observation = _reader_observation(streams)
        except CensusError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise CensusError("P004_READER_FAILED") from error
    producer_after = _producer_hashes()
    _fail(producer_after == producer_before, "PRODUCER_IDENTITY_DRIFT")
    _, final_digest = _read_retained(Path(source), source_sha256)
    _fail(final_digest == digest, "SOURCE_CHANGED")
    return {
        "format": "plcman.gx-re-lab.gxw-census",
        "version": 1,
        "decision": "STRUCTURE_OBSERVED",
        "support_claim": "NOT_CLAIMED",
        "lifecycle": "NOT_RUN",
        "input": {"sha256": digest, "byte_count": len(body), "read_only_unchanged": True},
        "identity": {"input_sha256_before": digest, "input_sha256_after": final_digest,
                     "producer_files_sha256_before": producer_before, "producer_files_sha256_after": producer_after},
        "producer": {"adapter_tool_sha256": producer_before["gxw_census.py"],
                     "p004_reader_sha256": producer_before["gxw_ladder_reader.py"],
                     "p004_reader_executed": True,
                     "reader_scope": "public load_all_substreams, collect_pous, and pou_rows"},
        "container": {"format": "CFB", **header, "hdb_substream_count": len(stream_records),
                      "hdb_substreams": stream_records},
        "topology": observation,
        "semantic_coverage": {
            "pou": _unmeasured_coverage(observation["pou"]["observed_count"], "SOURCE_AUTHORITY_UNVERIFIED"),
            "record": _unmeasured_coverage(observation["record"]["reader_row_count"], "SOURCE_AUTHORITY_UNVERIFIED"),
        },
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
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".gxw-census-", suffix=".tmp", delete=False) as handle:
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
                   "report_sha256": hashlib.sha256(encoded).hexdigest()}
    except (CensusError, OSError, ValueError) as error:
        summary = {"decision": "BLOCKED", "lifecycle": "NOT_RUN",
                   "reason": error.code if isinstance(error, CensusError) else "GXW_CENSUS_FAILED"}
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["decision"] == "STRUCTURE_OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
