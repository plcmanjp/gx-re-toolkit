"""Synthetic schema checks; no private parser corpus is used."""
from __future__ import annotations

import hashlib
import unittest
from importlib import resources
from pathlib import Path
import site

from gx3_r_parser_toolkit.schema_validator import SchemaValidationError, load_schema, validate
import gx3_r_parser_toolkit


class SchemaSyntheticTests(unittest.TestCase):
    def test_embedded_schema_has_reviewed_bytes_and_rejects_invalid_root(self) -> None:
        roots = [Path(value).resolve() for value in site.getsitepackages()]
        self.assertTrue(any(Path(gx3_r_parser_toolkit.__file__).resolve().is_relative_to(root) for root in roots))
        resource = resources.files("gx3_r_parser_toolkit").joinpath("schemas/neutral-ir-1.0.0.schema.json")
        self.assertEqual("26ac430cef74466116d2607e8136feb648b7ebef222ace22dc6798fb529c095f", hashlib.sha256(resource.read_bytes()).hexdigest())
        with self.assertRaises(SchemaValidationError):
            validate({"format": "synthetic-invalid"}, load_schema())


if __name__ == "__main__":
    unittest.main()
