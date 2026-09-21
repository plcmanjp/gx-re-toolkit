"""Fail-closed, read-only GX3 ZIP and SQLite access."""

from __future__ import annotations

import hashlib
import io
import os
import re
import sqlite3
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Self


@dataclass(frozen=True)
class ArchiveBudget:
    max_input_bytes: int = 256 * 1024 * 1024
    max_entries: int = 10_000
    max_entry_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_compression_ratio: int = 1_000
    max_path_depth: int = 32
    max_path_length: int = 512


@dataclass(frozen=True)
class SqliteEvidence:
    entry: str
    byte_count: int
    sha256: str
    schema_sha256: str
    table_count: int


class SafeGx3Archive:
    """Immutable in-memory snapshot with archive and SQLite validation."""

    def __init__(
        self, source: str | os.PathLike[str], budget: ArchiveBudget | None = None
    ):
        requested = Path(source).absolute()
        self._requested_path = requested
        self.path = requested
        self.budget = budget or ArchiveBudget()
        self._assert_regular_source()
        self.path = requested.resolve(strict=True)
        self._resolved_path = self.path
        before = self.path.stat()
        if before.st_size > self.budget.max_input_bytes:
            raise ValueError("GX3 input exceeds the configured byte budget")
        self._blob = self.path.read_bytes()
        if len(self._blob) > self.budget.max_input_bytes:
            raise ValueError(
                "GX3 input exceeded the configured byte budget while reading"
            )
        after = self.path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("GX3 input changed while the immutable snapshot was read")
        self.byte_count = len(self._blob)
        self.sha256 = hashlib.sha256(self._blob).hexdigest()
        self._zip = zipfile.ZipFile(io.BytesIO(self._blob), "r")
        try:
            self.archive_entry_count = len(self._zip.infolist())
            self.entries = self._validate_entries()
            self.sqlite_evidence = tuple(
                self._validate_sqlite(name)
                for name in sorted(self.entries)
                if name.lower().endswith(".db")
            )
        except Exception:
            self._zip.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def close(self) -> None:
        self._zip.close()
        self.path = self._requested_path
        self._assert_regular_source()
        if self._requested_path.resolve(strict=True) != self._resolved_path:
            raise ValueError("GX3 input target changed during inspection")
        self.path = self._resolved_path
        current = self.path.read_bytes()
        if (
            len(current) != self.byte_count
            or hashlib.sha256(current).hexdigest() != self.sha256
        ):
            raise ValueError("GX3 input changed during inspection")

    def _assert_regular_source(self) -> None:
        if self.path.suffix.casefold() != ".gx3":
            raise ValueError("input must have a .gx3 extension")
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or self.path.is_symlink():
            raise ValueError("GX3 input must be a regular, non-link file")
        for part in (self.path, *self.path.parents):
            attrs = getattr(part.lstat(), "st_file_attributes", 0)
            if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                raise ValueError("GX3 input path must not traverse a reparse point")

    @staticmethod
    def _normalize(name: str) -> str:
        name = name.replace("\\", "/")
        if not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
            raise ValueError("archive contains an absolute or empty path")
        if any(ord(char) < 32 or ord(char) == 127 for char in name):
            raise ValueError("archive path contains a control character")
        parts = PurePosixPath(name).parts
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise ValueError("archive path contains an unsafe segment")
        return "/".join(parts)

    def _validate_entries(self) -> dict[str, zipfile.ZipInfo]:
        infos = self._zip.infolist()
        if not infos or len(infos) > self.budget.max_entries:
            raise ValueError("archive entry count is outside the configured budget")
        result: dict[str, zipfile.ZipInfo] = {}
        folded: set[str] = set()
        total = 0
        for info in infos:
            name = self._normalize(info.filename)
            if name in result or name.casefold() in folded:
                raise ValueError(
                    "archive contains duplicate or case-fold-colliding paths"
                )
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode) or (
                file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))
            ):
                raise ValueError("archive contains a non-regular entry")
            if (
                len(name) > self.budget.max_path_length
                or len(PurePosixPath(name).parts) > self.budget.max_path_depth
            ):
                raise ValueError("archive path exceeds the configured budget")
            if info.is_dir():
                if info.file_size:
                    raise ValueError("archive directory entry has an invalid payload")
                folded.add(name.casefold())
                continue
            if file_type and not stat.S_ISREG(mode):
                raise ValueError("archive contains a non-regular file entry")
            if info.file_size > self.budget.max_entry_bytes:
                raise ValueError("archive entry exceeds the configured byte budget")
            total += info.file_size
            if total > self.budget.max_total_bytes:
                raise ValueError(
                    "archive uncompressed total exceeds the configured budget"
                )
            if info.file_size and info.compress_size == 0:
                raise ValueError("archive entry has an invalid compression ratio")
            if (
                info.compress_size
                and info.file_size / info.compress_size
                > self.budget.max_compression_ratio
            ):
                raise ValueError(
                    "archive entry exceeds the configured compression ratio"
                )
            result[name] = info
            folded.add(name.casefold())
        return result

    def read(self, name: str) -> bytes:
        normalized = self._normalize(name)
        info = self.entries.get(normalized)
        if info is None:
            raise KeyError(normalized)
        body = self._zip.read(info)
        if len(body) != info.file_size:
            raise ValueError("archive entry length changed during read")
        return body

    def digest(self, name: str) -> str:
        return hashlib.sha256(self.read(name)).hexdigest()

    def _validate_sqlite(self, name: str) -> SqliteEvidence:
        body = self.read(name)
        if not body.startswith(b"SQLite format 3\x00"):
            raise ValueError(f"database entry lacks a SQLite header: {name}")
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(body)
            connection.execute("PRAGMA query_only = ON")
            if list(connection.execute("PRAGMA integrity_check")) != [("ok",)]:
                raise ValueError(f"SQLite integrity check failed: {name}")
            if list(connection.execute("PRAGMA foreign_key_check")):
                raise ValueError(f"SQLite foreign-key check failed: {name}")
            schema = list(
                connection.execute(
                    "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name, tbl_name"
                )
            )
            tables = [
                row
                for row in schema
                if row[0] == "table" and not row[1].startswith("sqlite_")
            ]
            encoded = repr(schema).encode("utf-8")
        except sqlite3.DatabaseError as error:
            raise ValueError(f"invalid SQLite entry: {name}") from error
        finally:
            connection.close()
        return SqliteEvidence(
            name,
            len(body),
            hashlib.sha256(body).hexdigest(),
            hashlib.sha256(encoded).hexdigest(),
            len(tables),
        )
