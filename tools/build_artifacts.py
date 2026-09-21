"""Build committed packages into a NEW external directory with source provenance.

Requires an isolated environment containing the recorded setuptools/build tools.
Does not install dependencies, publish artifacts, or modify the source checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

PACKAGES = {
    "packages/gx3-fx5": "gx3_fx5_parser_toolkit",
    "packages/gx3-r": "gx3_r_parser_toolkit",
    "packages/gxw-q": None,
    "lab": None,
}


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def build(root: Path, output: Path) -> dict:
    root = root.resolve(strict=True)
    output = output.absolute()
    overrides = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")
    if any(key in os.environ for key in overrides):
        raise ValueError("Git environment overrides are not allowed")
    if not (root / ".git").is_dir() or (root / ".git").is_symlink():
        raise ValueError("An independent checkout is required")
    if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise ValueError("Git root mismatch")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Commit the reviewed candidate first")
    if output.exists() or output.is_relative_to(root) or output.resolve().is_relative_to(root):
        raise ValueError("Output must be new and outside the checkout")
    for ancestor in output.parents:
        if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
            raise ValueError("Output link boundary is not allowed")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    epoch = git(root, "show", "-s", "--format=%ct", "HEAD").decode().strip()
    entries = []
    for row in git(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        metadata, raw_name = row.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        name = raw_name.decode("utf-8")
        path = PurePosixPath(name)
        if mode not in (b"100644", b"100755") or kind != b"blob" or path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Only regular committed package inputs are supported")
        entries.append((name, oid.decode()))
    required = {"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"} | {f"{package}/pyproject.toml" for package in PACKAGES}
    if not required <= {name for name, _ in entries}:
        raise ValueError("Required package or license inputs are absent")
    if any(name.endswith("/_provenance.json") for name, _ in entries):
        raise ValueError("Source provenance must be artifact-only")
    output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment.update(SOURCE_DATE_EPOCH=epoch, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    records = []
    for package, namespace in PACKAGES.items():
        stage = output / "staging" / package
        stage.mkdir(parents=True)
        for name, oid in entries:
            if name.startswith(package + "/"):
                relative = name[len(package) + 1:]
            elif name in {"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"}:
                relative = name
            else:
                continue
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(git(root, "cat-file", "blob", oid))
        if namespace:
            provenance = stage / "src" / namespace / "_provenance.json"
            with provenance.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump({"format": "gx-re-toolkit.source.v1", "source_commit": commit, "source_tree": tree}, stream, sort_keys=True)
                stream.write("\n")
        # Git has no file mtimes. Use the fixed commit epoch as build-input mtime,
        # never rewrite fixture contents or normalize an already built artifact.
        for path in stage.rglob("*"):
            os.utime(path, (int(epoch), int(epoch)))
        artifact_dir = output / "artifacts" / package
        artifact_dir.mkdir(parents=True)
        subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--wheel", "--sdist", "--outdir", str(artifact_dir), str(stage)],
                       check=True, env=environment)
        for artifact in sorted(artifact_dir.iterdir()):
            body = artifact.read_bytes()
            records.append({"path": artifact.relative_to(output).as_posix(), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
    result = {"format": "gx-re-toolkit.build.v1", "source_commit": commit, "source_tree": tree,
              "source_date_epoch": epoch, "python": sys.version, "platform": sys.platform,
              "tools": {name: importlib.metadata.version(name) for name in ("build", "setuptools", "packaging", "pyproject_hooks")},
              "artifacts": records, "published": False}
    with (output / "build-manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build(Path(__file__).resolve().parents[1], args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
