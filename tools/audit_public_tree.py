"""Bounded content audit of the worktree, every local ref, and package archives.

This pattern/allowlist check is not a legal opinion or an exhaustive secret scan.
Run additional private vocabulary checks outside this repository before release.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
SCHEMA_PINS = {
    "b42b578be8b10190c4a7e8ff7dc52dda05b1e30cd1a21a03b16b92a51eb4f6ed",
    "26ac430cef74466116d2607e8136feb648b7ebef222ace22dc6798fb529c095f",
}
ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".json", ".txt", ".yml", ".yaml", ".cfg"}
ALLOWED_NAMES = {"LICENSE", "NOTICE", "PKG-INFO", "METADATA", "WHEEL", "RECORD", ".gitignore", ".gitattributes"}
RULES = {
    "private-layout": re.compile(r"(?:Project[/\\]P\d{3}|001-plc-workspace|OneDrive[/\\]|[A-Za-z]:[/\\]Users[/\\])"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,})"),
}


def inspect(name: str, body: bytes) -> list[str]:
    path = PurePosixPath(name)
    errors = []
    if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        errors.append("unsafe-name")
    if len(body) > MAX_FILE:
        return errors + ["file-cap"]
    if path.suffix not in ALLOWED_SUFFIXES and path.name not in ALLOWED_NAMES:
        errors.append("unapproved-file-type")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return errors + ["non-utf8"]
    digest = hashlib.sha256(body).hexdigest()
    # Exact immutable profile schemas retain their existing embedded identifier.
    if digest in SCHEMA_PINS:
        text = text.replace("https://github.com/plcmanjp/001-plc-workspace/neutral-ir-1.0.0.schema.json", "schema-identifier")
    # The scanner's own literal rules are configuration, not private input.
    if name.endswith("tools/audit_public_tree.py"):
        text = "\n".join(line for line in text.splitlines() if not any(key in line for key in ('"private-layout":', 'text = text.replace(')))
    for rule, pattern in RULES.items():
        if pattern.search(text):
            errors.append(rule)
    if text.startswith("\ufeff"):
        errors.append("bom")
    return errors


def archive_entries(path: Path):
    total = 0
    if path.suffix in {".whl", ".zip"}:
        with zipfile.ZipFile(path) as archive:
            seen = set()
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                if entry.filename in seen or entry.file_size > MAX_FILE:
                    raise ValueError("Duplicate or oversized archive entry")
                seen.add(entry.filename)
                total += entry.file_size
                if total > MAX_TOTAL or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Archive cap or link")
                yield entry.filename, archive.read(entry)
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            seen = set()
            for entry in archive:
                if entry.isdir():
                    continue
                if not entry.isfile() or entry.name in seen or entry.size > MAX_FILE:
                    raise ValueError("Unapproved archive member")
                seen.add(entry.name)
                total += entry.size
                if total > MAX_TOTAL:
                    raise ValueError("Archive cap")
                with archive.extractfile(entry) as stream:
                    yield entry.name, stream.read(MAX_FILE + 1)
    else:
        raise ValueError("Unapproved archive format")


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def audit(root: Path, artifacts: list[Path]) -> dict:
    if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root.resolve():
        raise ValueError("Independent Git root required")
    failures = []
    records = []
    def check(scope, name, body):
        errors = inspect(name, body)
        records.append({"scope": scope, "path": name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
        failures.extend({"scope": scope, "path": name, "rule": error} for error in errors)
    names = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    for raw in sorted(set(names) - {b""}):
        name = raw.decode("utf-8")
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unapproved worktree member")
        check("worktree", name, path.read_bytes())
    commits = git(root, "rev-list", "--all").decode().splitlines()
    seen = set()
    for commit in commits:
        for raw in git(root, "ls-tree", "-rz", commit).split(b"\0"):
            if not raw:
                continue
            metadata, raw_name = raw.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            name = raw_name.decode("utf-8")
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise ValueError("Unapproved history member")
            if (name, oid) not in seen:
                seen.add((name, oid))
                check("history", name, git(root, "cat-file", "blob", oid.decode()))
    for artifact in artifacts:
        for name, body in archive_entries(artifact):
            check(artifact.name, name, body)
    return {"status": "PASS" if not failures else "FAIL", "commits": commits,
            "refs": git(root, "for-each-ref", "--format=%(refname) %(objectname)").decode().splitlines(),
            "checked": len(records), "files": records, "failures": failures,
            "limitations": ["Not exhaustive secret detection", "No independent legal clearance", "Private vocabulary audit is separate"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", action="append", default=[], type=Path)
    args = parser.parse_args()
    result = audit(Path(__file__).resolve().parents[1], args.artifact)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
