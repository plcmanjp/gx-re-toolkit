"""Finite GXW OLE reads shared by the reader and candidate writers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import olefile

MAX_CONTAINER_BYTES = 512 * 1024 * 1024
MAX_STREAM_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_STREAMS = 10000


def open_file(path: str | Path) -> olefile.OleFileIO:
    source = Path(path)
    if not source.is_file() or source.stat().st_size > MAX_CONTAINER_BYTES:
        raise ValueError("GXW container exceeds the byte budget or is not a file")
    return olefile.OleFileIO(str(source))


def open_nested(body: bytes) -> olefile.OleFileIO:
    if len(body) > MAX_CONTAINER_BYTES:
        raise ValueError("nested OLE container exceeds the byte budget")
    from io import BytesIO
    return olefile.OleFileIO(BytesIO(body))


def stream(ole: Any, name: str | list[str], *, limit: int = MAX_STREAM_BYTES) -> bytes:
    declared = ole.get_size(name)
    if not isinstance(declared, int) or declared < 0 or declared > limit:
        raise ValueError("OLE stream declared size exceeds the byte budget")
    handle = ole.openstream(name)
    try:
        body = handle.read(declared + 1)
    finally:
        handle.close()
    if len(body) != declared:
        raise ValueError("OLE stream actual size differs from its declared size")
    return body


def all_streams(ole: Any) -> dict[str, bytes]:
    names = ole.listdir(streams=True)
    if len(names) > MAX_STREAMS:
        raise ValueError("OLE stream count exceeds the budget")
    keys: list[str] = []
    folded: set[str] = set()
    for name in names:
        if not isinstance(name, (list, tuple)) or not name or any(
            not isinstance(part, str) or not part or "/" in part or "\\" in part
            for part in name
        ):
            raise ValueError("OLE stream path has an unsafe segment")
        key = "/".join(name)
        if key.casefold() in folded:
            raise ValueError("OLE stream paths collide after normalization")
        folded.add(key.casefold())
        keys.append(key)
    sizes = [ole.get_size(name) for name in names]
    if any(not isinstance(size, int) or size < 0 or size > MAX_STREAM_BYTES for size in sizes):
        raise ValueError("OLE stream declared size exceeds the byte budget")
    if sum(sizes) > MAX_TOTAL_BYTES:
        raise ValueError("OLE aggregate declared size exceeds the byte budget")
    return {key: stream(ole, name) for key, name in zip(keys, names)}
