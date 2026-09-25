"""Same public $id/version never selects the other profile's schema."""

import hashlib
import json
import unittest
from importlib import resources

from gx3_fx5_parser_toolkit.ir import validate_ir as validate_fx5
from gx3_r_parser_toolkit.parser import validate_ir as validate_r
from gx3_r_parser_toolkit.schema_validator import SchemaValidationError, validate as validate_r_schema


class SchemaSelectionTests(unittest.TestCase):
    def test_existing_schema_bytes_and_cross_profile_finding(self):
        fx5 = resources.files("gx3_fx5_parser_toolkit").joinpath("schemas/neutral-ir-1.0.0.schema.json").read_bytes()
        r = resources.files("gx3_r_parser_toolkit").joinpath("schemas/neutral-ir-1.0.0.schema.json").read_bytes()
        self.assertEqual(hashlib.sha256(fx5).hexdigest(), "b42b578be8b10190c4a7e8ff7dc52dda05b1e30cd1a21a03b16b92a51eb4f6ed")
        self.assertEqual(hashlib.sha256(r).hexdigest(), "26ac430cef74466116d2607e8136feb648b7ebef222ace22dc6798fb529c095f")
        fx5_schema, r_schema = json.loads(fx5), json.loads(r)
        self.assertEqual(fx5_schema["$id"], r_schema["$id"])
        finding = {"finding_code": "SOURCE_GLOBAL_ORDER_NOT_SERIALIZED", "scope": "project",
                   "object_kind": "topology", "locator": "link", "digest": "0" * 64, "reason": "synthetic"}
        self.assertIn(finding["finding_code"], fx5_schema["$defs"]["finding"]["properties"]["finding_code"]["enum"])
        with self.assertRaises(SchemaValidationError):
            validate_r_schema(finding, {"$defs": r_schema["$defs"], "$ref": "#/$defs/finding"})

    def test_ir_entrypoints_require_package_and_profile(self):
        for validator in (validate_fx5, validate_r):
            with self.subTest(validator=validator), self.assertRaisesRegex(ValueError, "identity mismatch"):
                validator({"schema_name": "plcman.gx3.neutral-ir", "schema_version": "1.0.0",
                           "producer": {"package": "wrong"}, "profile": {"profile_id": "wrong", "family": "wrong"}})
            for malformed in (None, {"producer": None}, {"producer": {}, "profile": None}):
                with self.subTest(validator=validator, malformed=malformed), self.assertRaises(ValueError):
                    validator(malformed)


if __name__ == "__main__":
    unittest.main()
