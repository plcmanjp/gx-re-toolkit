"""Synthetic schema checks; no private parser corpus is used."""
from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from importlib import resources
from pathlib import Path
import site
import sys
import tempfile
import zipfile

from gx3_r_parser_toolkit.schema_validator import SchemaValidationError, load_schema, validate
import gx3_r_parser_toolkit
from gx3_r_parser_toolkit.cli import _summary


class SchemaSyntheticTests(unittest.TestCase):
    def test_embedded_schema_has_reviewed_bytes_and_rejects_invalid_root(self) -> None:
        roots = [Path(value).resolve() for value in site.getsitepackages()]
        self.assertTrue(any(Path(gx3_r_parser_toolkit.__file__).resolve().is_relative_to(root) for root in roots))
        resource = resources.files("gx3_r_parser_toolkit").joinpath("schemas/neutral-ir-1.0.0.schema.json")
        self.assertEqual("26ac430cef74466116d2607e8136feb648b7ebef222ace22dc6798fb529c095f", hashlib.sha256(resource.read_bytes()).hexdigest())
        with self.assertRaises(SchemaValidationError):
            validate({"format": "synthetic-invalid"}, load_schema())


class SummarySyntheticTests(unittest.TestCase):
    """Exercise the installed production entry point with disposable GX3 files."""

    def _run_cli(self, *args: Path | str) -> subprocess.CompletedProcess[str]:
        command = Path(sys.executable).with_name(
            "gx3-r-inspect.exe" if sys.platform == "win32" else "gx3-r-inspect"
        )
        self.assertTrue(command.is_file(), "installed gx3-r-inspect entry point is required")
        self.assertEqual(Path(sys.executable).resolve().parent, command.resolve().parent)
        roots = [Path(value).resolve() for value in site.getsitepackages()]
        self.assertTrue(
            any(Path(gx3_r_parser_toolkit.__file__).resolve().is_relative_to(root) for root in roots),
            "test must import the installed gx3-r-parser-toolkit package",
        )
        return subprocess.run(
            [str(command), *(str(arg) for arg in args)],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="strict",
            timeout=30,
        )

    def _partial_archive(self, directory: Path) -> Path:
        source = directory / "summary-marker.gx3"
        marker = "SYNTHETIC_PRIVATE_MARKER"
        config = '<Root><Config Unit="R04" UnitId="4097" Note="%s"/></Root>' % marker
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("Config.xml", config)
            archive.writestr("!!Config.xml", config)
            archive.writestr(f"{marker}/PouLinkOrder.info", "7\n")
            archive.writestr(f"{marker}/Program.qpg", f"{marker}_POU\0".encode("utf-16le"))
        return source

    def test_summary_is_fixed_allowlist_for_partial_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._partial_archive(Path(directory))
            completed = self._run_cli(source, "--summary")
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual({"coverage", "finding_count", "status", "support_status"}, set(result))
        self.assertEqual("PARTIAL", result["status"])
        self.assertEqual("SUPPORTED", result["support_status"])
        self.assertGreater(result["finding_count"], 0)
        self.assertEqual({"project", "pou", "record", "comment", "label"}, set(result["coverage"]))
        self.assertLessEqual(len(completed.stdout.encode("utf-8")), 8 * 1024)
        self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", completed.stdout)

    def test_summary_handles_empty_and_fatal_inputs_without_reason_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty.gx3"
            with zipfile.ZipFile(empty, "w"):
                pass
            empty_completed = self._run_cli(empty, "--summary")
            fatal = root / "fatal.gx3"
            fatal.write_bytes(b"SYNTHETIC_FATAL_MARKER")
            fatal_completed = self._run_cli(fatal, "--summary")
            fatal_output = root / "fatal-artifact"
            fatal_output_completed = self._run_cli(
                fatal, "--summary", "--output", fatal_output
            )
        self.assertEqual(0, empty_completed.returncode, empty_completed.stderr)
        empty_result = json.loads(empty_completed.stdout)
        self.assertEqual("PARTIAL", empty_result["status"])
        self.assertEqual("AMBIGUOUS", empty_result["support_status"])
        self.assertEqual(3, fatal_completed.returncode)
        fatal_result = json.loads(fatal_completed.stdout)
        self.assertEqual("FATAL", fatal_result["status"])
        self.assertIsNone(fatal_result["support_status"])
        self.assertIsNone(fatal_result["coverage"])
        self.assertEqual(1, fatal_result["finding_count"])
        self.assertNotIn("SYNTHETIC_FATAL_MARKER", fatal_completed.stdout)
        self.assertNotIn("not a ZIP container", fatal_completed.stdout)
        self.assertEqual(2, fatal_output_completed.returncode)
        self.assertFalse(fatal_output.exists())

    def test_default_and_output_remain_full_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._partial_archive(root)
            default_completed = self._run_cli(source)
            output = root / "artifact"
            output_completed = self._run_cli(source, "--output", output)
            summary_output = root / "summary-artifact"
            summary_completed = self._run_cli(source, "--summary", "--output", summary_output)
            published = json.loads((output / "neutral-ir.json").read_text(encoding="ascii"))
            summary_published = json.loads(
                (summary_output / "neutral-ir.json").read_text(encoding="ascii")
            )
        self.assertEqual(0, default_completed.returncode, default_completed.stderr)
        self.assertEqual(0, output_completed.returncode, output_completed.stderr)
        self.assertEqual(0, summary_completed.returncode, summary_completed.stderr)
        default_result = json.loads(default_completed.stdout)
        self.assertIn("pous", default_result)
        self.assertIn("SYNTHETIC_PRIVATE_MARKER", default_completed.stdout)
        self.assertEqual(default_result, json.loads(output_completed.stdout))
        self.assertEqual(default_result, published)
        summary_result = json.loads(summary_completed.stdout)
        self.assertEqual({"coverage", "finding_count", "status", "support_status"}, set(summary_result))
        self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", summary_completed.stdout)
        self.assertEqual(default_result, summary_published)

    def test_summary_does_not_copy_unapproved_strings_from_a_result(self) -> None:
        marker = "SYNTHETIC_SECRET_VALUE"
        result = {
            "profile": {"detector_status": "SUPPORTED", "name": marker},
            "coverage": {
                kind: {"total": 0, "decoded": 0, "partial": 0, "unknown": 0}
                for kind in ("project", "pou", "record", "comment", "label")
            },
            "findings": [],
            "pous": [{"name": marker, "records": [{"operands": [marker]}]}],
            "comments": [{"value": marker}],
            "labels": [{"value": marker}],
        }
        projection = _summary(result)
        self.assertEqual("FULL", projection["status"])
        self.assertNotIn(marker, json.dumps(projection, sort_keys=True))
        result["findings"] = [{"reason": marker, "locator": marker}]
        partial_projection = _summary(result)
        self.assertEqual("PARTIAL", partial_projection["status"])
        self.assertNotIn(marker, json.dumps(partial_projection, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
