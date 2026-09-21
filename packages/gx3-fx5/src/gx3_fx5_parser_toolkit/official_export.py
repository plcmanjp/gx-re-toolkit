"""Strict, read-only parsers for GX Works3 official export artifacts."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any


LADDER_HEADER = [
    "Step No.",
    "Line Statement",
    "Instruction",
    "I/O (Device)",
    "Blank",
    "P/I Statement",
    "Note",
]
LOCAL_LABEL_HEADER = [
    "Class", "Label Name", "Data Type", "Constant", "Initial Value",
    "Assign (Device/Label)", "Address", "Comment", "Comment 2", "Comment 3",
    "Comment 4", "Comment 5", "Japanese/日本語", "English",
    "Chinese Simplified/简体中文", "Korean/한국어", "Chinese Traditional/繁體中文",
    "German/Deutsch", "Italian/Italiano", "Reserved1", "Reserved2", "Reserved3",
    "Reserved4", "Remark", "System Label Relation", "System Label Name", "Attribute",
]
GLOBAL_LABEL_HEADER = [*LOCAL_LABEL_HEADER, "Access from External Device"]
COMMENT_HEADER = ["Device Name", "English"]


def _utf16le_tsv(path: Path, kind: str) -> list[list[str]]:
    raw = path.read_bytes()
    if not raw.startswith(b"\xff\xfe"):
        raise ValueError(f"official {kind} export is not UTF-16LE BOM")
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-16"), newline=""), delimiter="\t"))
    except UnicodeDecodeError as error:
        raise ValueError(f"official {kind} export is not valid UTF-16LE") from error
    if not rows:
        raise ValueError(f"official {kind} export is empty")
    return rows


def read_ladder_tsv(path: Path) -> dict[str, Any]:
    """Read all seven GX Works3 Ladder columns without normalizing values."""
    rows = _utf16le_tsv(path, "Ladder")
    if len(rows) < 3 or len(rows[0]) != 1 or not rows[0][0]:
        raise ValueError("official Ladder export has no project row")
    if len(rows[1]) != 2 or not rows[1][0]:
        raise ValueError("official Ladder export has no module row")
    if rows[2] != LADDER_HEADER:
        raise ValueError("official Ladder export header differs from GX Works3 schema")
    body = rows[3:]
    if any(len(row) != 7 for row in body):
        raise ValueError("official Ladder export has a non-seven-column row")
    return {"project": rows[0][0], "module": rows[1], "header": rows[2], "rows": body}


def read_comment_tsv(path: Path) -> dict[str, Any]:
    """Read a strict two-header-row device comment export without coercion."""
    rows = _utf16le_tsv(path, "comment")
    if len(rows) < 2 or len(rows[0]) != 1 or not rows[0][0]:
        raise ValueError("official comment export has no project row")
    header = rows[1]
    if header != COMMENT_HEADER:
        raise ValueError("official comment export header differs from GX Works3 schema")
    body = rows[2:]
    if any(len(row) != 2 for row in body):
        raise ValueError("official comment export has an inconsistent row width")
    return {"project": rows[0][0], "header": header, "rows": body}


def read_label_tsv(path: Path, category: str) -> dict[str, Any]:
    """Read a strict two-header-row label export without reordering rows or cells."""
    rows = _utf16le_tsv(path, "label")
    if len(rows) < 2 or len(rows[0]) != 1 or not rows[0][0]:
        raise ValueError("official label export has no project row")
    expected = {
        "global_label": GLOBAL_LABEL_HEADER,
        "local_label": LOCAL_LABEL_HEADER,
    }.get(category)
    if expected is None:
        raise ValueError("official label export category is unsupported")
    header = rows[1]
    if header != expected:
        raise ValueError("official label export header differs from GX Works3 schema")
    body = rows[2:]
    if any(len(row) != len(header) for row in body):
        raise ValueError("official label export has an inconsistent row width")
    return {"project": rows[0][0], "header": header, "rows": body}
