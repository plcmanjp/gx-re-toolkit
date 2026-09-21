"""Bounded retained-input snapshot; no project-conversion dependency."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
import stat
from pathlib import Path

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024

class ConversionError(ValueError):
    """Snapshot input rejected."""

def _handle_final_path(descriptor: int) -> str:
    """Return the kernel-resolved path of an open descriptor."""
    if os.name == "nt":
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(descriptor)
        buffer = ctypes.create_unicode_buffer(32_768)
        from ctypes import wintypes
        get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
        get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_final_path.restype = wintypes.DWORD
        length = get_final_path(wintypes.HANDLE(handle), buffer, len(buffer), 0)
        if length == 0 or length >= len(buffer):
            raise OSError("could not resolve open handle path")
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return os.path.normcase(os.path.abspath(value))
    return os.path.normcase(os.path.abspath(os.readlink(f"/proc/self/fd/{descriptor}")))


def _stat_identity(stat_result: os.stat_result) -> tuple[int, int, int, int]:
    return stat_result.st_dev, stat_result.st_ino, stat_result.st_size, stat_result.st_mtime_ns


@dataclass
class InputSnapshot:
    """One no-follow input handle whose exact bytes drive parse and publication."""

    descriptor: int
    path: Path
    body: bytes
    sha256: str
    identity: tuple[int, int, int, int]
    final_path: str

    def verify(self) -> None:
        if _stat_identity(os.fstat(self.descriptor)) != self.identity:
            raise RuntimeError("input handle identity changed during conversion")
        if _handle_final_path(self.descriptor) != self.final_path:
            raise RuntimeError("input handle final path changed during conversion")
        path_stat = os.stat(self.path, follow_symlinks=False)
        if _stat_identity(path_stat) != self.identity or os.path.normcase(os.path.abspath(self.path.resolve())) != self.final_path:
            raise RuntimeError("input path no longer identifies the parsed snapshot")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _open_input_snapshot(path: Path) -> InputSnapshot:
    """Open once, read within the cap, and retain the handle through publish."""
    path = _reject_link_like_ancestors(path, "input")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_ARCHIVE_BYTES:
            raise ConversionError("input exceeds type or byte limit")
        identity = _stat_identity(opened)
        final_path = _handle_final_path(descriptor)
        intended = os.path.normcase(os.path.abspath(path.resolve()))
        if final_path != intended:
            raise ConversionError("--input handle final path differs from the validated path")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, MAX_ARCHIVE_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            if total > MAX_ARCHIVE_BYTES:
                raise ConversionError("--input GX3 archive exceeds byte limit")
            chunks.append(block)
        body = b"".join(chunks)
        snapshot = InputSnapshot(descriptor, path, body, hashlib.sha256(body).hexdigest(), identity, final_path)
        snapshot.verify()
        return snapshot
    except Exception:
        os.close(descriptor)
        raise


def _is_link_like(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(is_junction) and bool(is_junction()))


def _reject_link_like_ancestors(path: Path, label: str) -> Path:
    current = path.absolute()
    while True:
        if current.exists() and _is_link_like(current):
            raise ConversionError(f"{label} must not traverse a link-like path: {current}")
        if current.parent == current:
            return path.absolute()
        current = current.parent
