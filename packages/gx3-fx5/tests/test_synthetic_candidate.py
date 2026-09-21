"""Synthetic package checks; no private project fixture is used."""
from __future__ import annotations

import tempfile
import unittest
from importlib import resources
from pathlib import Path
import site

from gx3_core import SafeGx3Archive
import gx3_fx5_parser_toolkit


class SafeArchiveSyntheticTests(unittest.TestCase):
    def test_subjects_are_installed_and_schema_is_a_package_resource(self) -> None:
        roots = [Path(value).resolve() for value in site.getsitepackages()]
        self.assertTrue(any(Path(gx3_fx5_parser_toolkit.__file__).resolve().is_relative_to(root) for root in roots))
        schema = resources.files("gx3_fx5_parser_toolkit").joinpath("schemas/neutral-ir-1.0.0.schema.json")
        self.assertTrue(schema.is_file())

    def test_rejects_non_gx3_input_before_opening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-an-archive.txt"
            path.write_bytes(b"synthetic")
            with self.assertRaisesRegex(ValueError, "\\.gx3"):
                SafeGx3Archive(path)


if __name__ == "__main__":
    unittest.main()
