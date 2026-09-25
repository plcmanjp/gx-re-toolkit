"""Small, deterministic XML boundary checks against the installed package."""

import random
import unittest
import xml.etree.ElementTree as ET

from gx3_core.xml import MAX_XML_BYTES, parse_xml


class XmlBudgetTests(unittest.TestCase):
    def test_valid_namespace_and_comment_are_preserved(self):
        body = b'<Root xmlns="urn:synthetic"><!-- <!DOCTYPE is a comment --><Config Unit="FX5U" UnitId="528"/></Root>'
        root = parse_xml(body)
        self.assertEqual(root.tag, "{urn:synthetic}Root")
        self.assertEqual(root[0].attrib, {"Unit": "FX5U", "UnitId": "528"})

    def test_declarations_depth_nodes_encoding_and_bytes_are_bounded(self):
        cases = (
            b'<!DOCTYPE Config [<!ENTITY x "a">]><Config>&x;</Config>',
            b'<Config><' + b'A>' * 65 + b'</A>' * 65 + b'</Config>',
            b'<Config>' + b'<A/>' * 10001 + b'</Config>',
            b'\xff<Config/>',
            b'<Config>' + b' ' * MAX_XML_BYTES + b'</Config>',
        )
        for body in cases:
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                parse_xml(body)

    def test_bounded_fixed_seed_mutation_fails_closed(self):
        seed = 6204
        rng = random.Random(seed)
        baseline = b'<Config Unit="FX5U" UnitId="528"/>'
        for case in range(64):
            data = bytearray(baseline)
            data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                root = parse_xml(bytes(data))
            except ValueError:
                continue
            self.assertTrue(root.tag, f"seed={seed} case={case} input={data.hex()}")
            self.assertTrue(ET.tostring(root), f"seed={seed} case={case} input={data.hex()}")


if __name__ == "__main__":
    unittest.main()
