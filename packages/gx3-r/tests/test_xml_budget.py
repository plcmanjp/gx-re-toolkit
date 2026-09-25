"""R profile XML gate uses its own package boundary."""

import unittest

from gx3_r_parser_toolkit.xml import parse_xml


class XmlBudgetTests(unittest.TestCase):
    def test_r_config_and_declared_entity(self):
        self.assertEqual(parse_xml(b'<Config Unit="R04" UnitId="4097"/>').get("Unit"), "R04")
        with self.assertRaisesRegex(ValueError, "DTD"):
            parse_xml(b'<!DOCTYPE Config [<!ENTITY x "R04">]><Config Unit="&x;"/>')

    def test_node_and_depth_limits(self):
        with self.assertRaises(ValueError):
            parse_xml(b'<R>' + b'<N/>' * 10001 + b'</R>')
        with self.assertRaises(ValueError):
            parse_xml(b'<N>' * 65 + b'</N>' * 65)


if __name__ == "__main__":
    unittest.main()
