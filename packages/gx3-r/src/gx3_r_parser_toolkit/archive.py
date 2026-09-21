from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import sqlite3
import stat
import zipfile

MAX_SQLITE_PAGES = 1_000_000
MAX_SQLITE_TABLES = 2_048
MAX_SQLITE_SCHEMA_BYTES = 4 * 1024 * 1024
MAX_SQLITE_ROWS_PER_TABLE = 5_000_000


class ArchiveError(ValueError):
    """Fatal malformed or unsafe container error; distinct from MINING_REQUIRED."""


def _reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.stat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


class SafeGx3Archive:
    """Read a GX3 ZIP into bounded memory and validate each SQLite carrier."""

    max_entries = 10_000
    max_input_bytes = 512 * 1024 * 1024
    max_member_bytes = 128 * 1024 * 1024
    max_total_bytes = 512 * 1024 * 1024
    max_ratio = 1_000

    def __init__(self, source: Path) -> None:
        self.source = source
        if source.suffix.casefold() != ".gx3":
            raise ArchiveError("input suffix must be .gx3")
        if not source.is_file() or _reparse(source) or any(_reparse(parent) for parent in source.absolute().parents):
            raise ArchiveError("input is not a regular file")
        before = source.stat()
        before_target = source.resolve(strict=True)
        before_identity = (before.st_dev, before.st_ino)
        if before.st_size > self.max_input_bytes:
            raise ArchiveError("input byte limit exceeded")
        if not zipfile.is_zipfile(source):
            raise ArchiveError("not a ZIP container")
        self.input_sha256 = sha256_file(source)
        self.entries: dict[str, bytes] = {}
        self.sqlite_evidence: dict[str, dict[str, object]] = {}
        with zipfile.ZipFile(source) as package:
            infos = package.infolist()
            if len(infos) > self.max_entries:
                raise ArchiveError("archive entry limit exceeded")
            total = sum(info.file_size for info in infos)
            compressed = sum(info.compress_size for info in infos)
            if total > self.max_total_bytes or total / max(compressed, 1) > self.max_ratio:
                raise ArchiveError("archive size or compression ratio limit exceeded")
            folded: set[str] = set()
            for info in sorted(infos, key=lambda value: value.filename):
                _safe_member(info)
                if info.is_dir():
                    continue
                if info.filename.casefold() in folded:
                    raise ArchiveError("case-fold duplicate archive entry")
                folded.add(info.filename.casefold())
                if info.filename in self.entries:
                    raise ArchiveError("duplicate archive entry")
                if _zip_link(info) or info.file_size > self.max_member_bytes:
                    raise ArchiveError("unsafe archive entry")
                if info.file_size / max(info.compress_size, 1) > self.max_ratio:
                    raise ArchiveError("entry compression ratio limit exceeded")
                try:
                    self.entries[info.filename] = package.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise ArchiveError("archive member read failed") from error
        for name, data in self.entries.items():
            if name.lower().endswith(".db"):
                try:
                    self.sqlite_evidence[name] = sqlite_evidence(data)
                except sqlite3.Error as error:
                    raise ArchiveError("SQLite validation failed") from error
        after = source.stat()
        after_target = source.resolve(strict=True)
        after_identity = (after.st_dev, after.st_ino)
        if before_target != after_target or before_identity != after_identity or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or self.input_sha256 != sha256_file(source):
            raise ArchiveError("input changed during archive read")

    def digest(self, name: str) -> str:
        return hashlib.sha256(self.entries[name]).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sqlite_connection(data: bytes, *, query_only: bool = True) -> sqlite3.Connection:
    if not data.startswith(b"SQLite format 3\x00"):
        raise ArchiveError("SQLite header is invalid")
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(data)
        if query_only:
            connection.execute("PRAGMA query_only=ON")
        pages = connection.execute("PRAGMA page_count").fetchone()[0]
        if not isinstance(pages, int) or pages > MAX_SQLITE_PAGES:
            raise ArchiveError("SQLite page budget exceeded")
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ArchiveError("SQLite integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ArchiveError("SQLite foreign-key check failed")
        return connection
    except sqlite3.Error as error:
        connection.close()
        raise ArchiveError("SQLite query failed") from error
    except BaseException:
        connection.close()
        raise


def sqlite_evidence(data: bytes) -> dict[str, object]:
    connection = sqlite_connection(data)
    try:
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        schema_bytes = connection.execute("SELECT COALESCE(SUM(length(sql)), 0) FROM sqlite_master").fetchone()[0]
        if len(tables) > MAX_SQLITE_TABLES or not isinstance(schema_bytes, int) or schema_bytes > MAX_SQLITE_SCHEMA_BYTES:
            raise ArchiveError("SQLite schema budget exceeded")
        row_counts: dict[str, int] = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            count = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
            if not isinstance(count, int) or count > MAX_SQLITE_ROWS_PER_TABLE:
                raise ArchiveError("SQLite row budget exceeded")
            row_counts[table] = count
        return {"sha256": hashlib.sha256(data).hexdigest(), "tables": tables, "row_counts": row_counts, "bytes": len(data)}
    finally:
        connection.close()


def _safe_member(info: zipfile.ZipInfo) -> None:
    name = info.filename
    posix, windows = PurePosixPath(name), PureWindowsPath(name)
    if not name or len(name) > 1024 or len(posix.parts) > 32 or any(ord(char) < 32 for char in name):
        raise ArchiveError("unsafe archive path")
    if not name or posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ArchiveError("unsafe archive path")
    if any(part in ("", ".", "..") for part in posix.parts) or any(part in (".", "..") for part in windows.parts):
        raise ArchiveError("unsafe archive path")


def _zip_link(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
