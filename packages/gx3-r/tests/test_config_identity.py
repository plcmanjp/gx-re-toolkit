"""Independent file-backed CPU identity regressions; no field acceptance."""
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from gx3_r_parser_toolkit.parser import parse


class ConfigIdentityTests(unittest.TestCase):
    def result(self, xml, mirror=None):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "identity.gx3"
            with ZipFile(source, "w") as output:
                output.writestr("Config.xml", xml)
                output.writestr("!!Config.xml", xml if mirror is None else mirror)
            before = source.read_bytes()
            result = parse(source)
            self.assertEqual(source.read_bytes(), before)
            return result

    def test_root_and_direct_wrapper(self):
        for xml in ('<Config Unit="R04" UnitId="4097"/>', '<Root><Config Unit="R04" UnitId="4097"/></Root>'):
            with self.subTest(xml=xml):
                self.assertEqual(self.result(xml)["profile"]["detector_status"], "SUPPORTED")

    def test_ambiguous_nodes_and_locations(self):
        supported = '<Config Unit="R04" UnitId="4097"/>'
        other = '<Config Unit="R08" UnitId="4098"/>'
        cases = [f"<Root>{supported}{other}</Root>", f"<Root>{other}{supported}</Root>",
                 f"<Root>{supported}{supported}</Root>", f"<Root>{supported}<Nested>{other}</Nested></Root>",
                 f"<Root><Nested>{other}</Nested>{supported}</Root>",
                 '<Config Unit="R04" UnitId="4097">' + other + '</Config>',
                 f"<Root><Nested>{supported}</Nested></Root>", "<Root/>"]
        for xml in cases:
            with self.subTest(xml=xml):
                result = self.result(xml)
                self.assertEqual(result["profile"]["detector_status"], "AMBIGUOUS")
                self.assertEqual(result["pous"], [])
                self.assertTrue(result["findings"])

    def test_dual_file_mismatch(self):
        result = self.result('<Config Unit="R04" UnitId="4097"/>', '<Config Unit="R08" UnitId="4098"/>')
        self.assertEqual(result["profile"]["detector_status"], "AMBIGUOUS")

    def test_single_unsupported_identity(self):
        self.assertEqual(self.result('<Root><Config Unit="R08" UnitId="4098"/></Root>')["profile"]["detector_status"], "UNSUPPORTED")

    def test_conflicting_evidence_is_order_independent(self):
        nodes = ['<Config Unit="R04" UnitId="4097"/>', '<Config Unit="R08" UnitId="4098"/>']
        reasons = [self.result('<Root>' + ''.join(ordered) + '</Root>')["findings"][0]["reason"] for ordered in (nodes, nodes[::-1])]
        self.assertEqual(reasons[0], reasons[1])
        self.assertIn("('R04', '4097')", reasons[0])
        self.assertIn("('R08', '4098')", reasons[0])
