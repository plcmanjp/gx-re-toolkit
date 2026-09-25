"""Verify normal installed distributions, resources, CLI imports and synthetic tests."""
from __future__ import annotations
import argparse
import hashlib
import importlib
from importlib import metadata, resources
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

VERSIONS = {"gx3-fx5-parser-toolkit": "0.4.0", "gx3-r-parser-toolkit": "0.2.0",
            "gxw-parser-toolkit": "0.1.0", "gx-re-lab": "0.1.0"}
SCHEMAS = {"gx3_fx5_parser_toolkit": "b42b578be8b10190c4a7e8ff7dc52dda05b1e30cd1a21a03b16b92a51eb4f6ed",
           "gx3_r_parser_toolkit": "26ac430cef74466116d2607e8136feb648b7ebef222ace22dc6798fb529c095f"}
LAB = "explorer_diff reference_query census r04_census gxw_census planner coverage_ledger external_compare final_scope lab experiment relation_audit campaign_coverage reducer table_delta snapshot".split()

def verify(root: Path, commit: str, tree: str, profiles: str = "all"):
    if sys.prefix == sys.base_prefix or os.environ.get("PYTHONPATH"):
        raise ValueError("Use an isolated venv without PYTHONPATH")
    origins = {}
    site_roots = [Path(p).resolve() for p in __import__("site").getsitepackages()]
    selected = VERSIONS if profiles == "all" else {key: VERSIONS[key] for key in ("gx3-fx5-parser-toolkit", "gx3-r-parser-toolkit")}
    for name, version in selected.items():
        if metadata.version(name) != version:
            raise ValueError("Distribution version mismatch: " + name)
        direct = metadata.distribution(name).read_text("direct_url.json")
        if direct and json.loads(direct).get("dir_info", {}).get("editable"):
            raise ValueError("Editable install is not evidence")
    names = ["gx3_core", "gx3_fx5_profile", "gx3_fx5_parser_toolkit.ir", "gx3_r_parser_toolkit.parser"]
    if profiles == "all":
        names += ["gxw_ladder_reader", "gxw_ladder_writer", "gxw_single_command", "gxw_pou_devmap", "gxw_reference_ir", "wt9_fill_pou_body", "gxw_bounded_ole", "gxw_bounded_xml"]
        names += ["gx_re_lab." + name for name in LAB]
    for name in names:
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve()
        if path.is_relative_to(root) or not any(path.is_relative_to(site) for site in site_roots):
            raise ValueError("Non-installed import: " + name)
        origins[name] = str(path)
    for namespace, expected in SCHEMAS.items():
        package = resources.files(namespace)
        body = package.joinpath("schemas/neutral-ir-1.0.0.schema.json").read_bytes()
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError("Schema drift")
        pin = json.loads(package.joinpath("_provenance.json").read_text(encoding="utf-8"))
        if pin["source_commit"] != commit or pin["source_tree"] != tree:
            raise ValueError("Artifact provenance mismatch")
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    cli = [("gx3-fx5-inspect", 0), ("gx3-r-inspect", 0)]
    if profiles == "all":
        cli += [("gxw-inspect", 1), ("gxw-write", 0), ("gxw-reference-ir", 0), ("gxw-encode", 0)]
    commands = [([str(Path(sys.executable).parent / (name + (".exe" if os.name == "nt" else ""))), "--help"], expected)
                for name, expected in cli]
    if profiles == "all":
        commands += [([sys.executable, "-B", "-m", "gx_re_lab." + name, "--help"], 0) for name in LAB[:13]]
        commands += [([sys.executable, "-B", "-m", "gxw_pou_devmap"], 1)]
    paths = ["packages/gx3-fx5/tests", "packages/gx3-r/tests"]
    if profiles == "all":
        paths += ["packages/gxw-q/tests", "lab/tests", "tools/tests"]
    commands += [([sys.executable, "-B", "-m", "unittest", "discover", "-s", str(root / path), "-v"], 0) for path in paths]
    records = []
    with tempfile.TemporaryDirectory(prefix="gx-install-check-") as temporary:
        for command, expected in commands:
            result = subprocess.run(command, cwd=temporary, env=environment, capture_output=True, timeout=120)
            text = (result.stdout + result.stderr).decode("utf-8", errors="strict")
            records.append({"command": command, "exit_code": result.returncode, "expected": expected, "output": text})
            if result.returncode != expected:
                raise ValueError("Install verification failed: " + repr(command) + "\n" + text)
    return {"status": "PASS", "profiles": profiles, "versions": selected, "origins": origins, "checks": records,
            "source_commit": commit, "source_tree": tree, "lifecycle": "NOT_RUN", "field_acceptance": "NOT_RUN"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profiles", choices=("all", "fx5-r"), default="all")
    args = parser.parse_args()
    if len(args.commit) != 40 or len(args.tree) != 40 or args.commit == "0" * 40:
        raise ValueError("Exact source identity required")
    result = verify(Path(__file__).resolve().parents[1], args.commit, args.tree, args.profiles)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print("PASS: installed resources, imports, CLI and synthetic tests")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
