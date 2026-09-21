"""Deterministic Phase 2 text and CSV projections."""

from __future__ import annotations

import csv
import io
import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Any

from gx3_fx5_profile.decoder import devmap


def _csv(rows: list[list[Any]]) -> bytes:
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    return stream.getvalue().encode("utf-8-sig")


def _safe_name(value: str) -> str:
    normalized = "".join(
        char if char.isalnum() or char in "-_" else "_" for char in value
    )
    return normalized[:80] or "POU"


def projection_files(ir: dict[str, Any]) -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "neutral-ir.json": (
            json.dumps(ir, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    }
    text: list[str] = []
    for pou in ir["pous"]:
        text.append(f"## POU {pou['execution_order']}: {pou['name']} [{pou['pou_id']}]")
        rows = [
            [
                "sequence",
                "step",
                "kind",
                "opcode",
                "operands",
                "text",
                "status",
                "record_id",
            ]
        ]
        for record in pou["records"]:
            operands = " ".join(item["raw_token"] for item in record["operands"])
            text.append(
                f"{record['sequence']:06d} {record['step'] if record['step'] is not None else '-'} {record['opcode'] or record['kind']} {operands}".rstrip()
            )
            rows.append(
                [
                    record["sequence"],
                    record["step"],
                    record["kind"],
                    record["opcode"],
                    operands,
                    record["text"],
                    record["status"],
                    record["record_id"],
                ]
            )
        files[f"pous/{pou['execution_order']:03d}-{_safe_name(pou['name'])}.csv"] = (
            _csv(rows)
        )
    files["records.txt"] = ("\n".join(text) + "\n").encode("utf-8")
    files["comments.csv"] = _csv(
        [
            [
                "scope",
                "program_id",
                "device_id",
                "language_slot",
                "value_state",
                "value",
                "locator",
            ]
        ]
        + [
            [
                item["scope"],
                item["program_id"],
                item["device_id"],
                item["language_slot"],
                item["value_state"],
                item["value"],
                item["provenance"]["source_locator"],
            ]
            for item in ir["comments"]
        ]
    )
    files["labels.csv"] = _csv(
        [
            [
                "scope",
                "program_id",
                "label_id",
                "language_slot",
                "value_state",
                "value",
                "locator",
            ]
        ]
        + [
            [
                item["scope"],
                item["program_id"],
                item["label_id"],
                item["language_slot"],
                item["value_state"],
                item["value"],
                item["provenance"]["source_locator"],
            ]
            for item in ir["labels"]
        ]
    )
    files["devmap.csv"] = _csv(
        [["device_id", "write_pous", "read_pous", "unknown_pous"]]
        + [
            [
                item["device_id"],
                "|".join(item["write_pous"]),
                "|".join(item["read_pous"]),
                "|".join(item["unknown_pous"]),
            ]
            for item in devmap(ir["pous"])
        ]
    )
    files["coverage.json"] = (
        json.dumps(
            {
                "coverage": ir["coverage"],
                "finding_count": len(ir["findings"]),
                "pou_finding_count": sum(len(item["findings"]) for item in ir["pous"]),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    return files


def publish_directory(target: Path, files: dict[str, bytes]) -> None:
    destination = target.resolve()
    if destination.exists():
        raise ValueError(
            "projection directory already exists; no-clobber policy blocked publication"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    temporary.mkdir()
    try:
        for relative, body in sorted(files.items()):
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        os.rename(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
