"""Independent file-backed CPU identity regressions; no field acceptance."""
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from gx3_core import SafeGx3Archive
from gx3_fx5_profile import detect, discover_project
from gx3_fx5_parser_toolkit.cli import inspect
from gx3_fx5_parser_toolkit.ir import build_neutral_ir
from test_installed_semantics import synthetic_gx3


class ConfigIdentityTests(unittest.TestCase):
    def archive(self, directory, xml, mirror=None):
        source = Path(directory) / "identity.gx3"
        base = Path(directory) / "base.gx3"
        synthetic_gx3(base)
        with ZipFile(base) as original, ZipFile(source, "w") as output:
            for name in original.namelist():
                output.writestr(name, xml if name == "Config.xml" else original.read(name))
            if mirror is not None:
                output.writestr("!!Config.xml", mirror)
        return source

    def test_root_and_direct_wrapper(self):
        for xml in ('<Config Unit="FX5U" UnitId="528"/>', '<Root><Config Unit="FX5U" UnitId="528"/></Root>'):
            with self.subTest(xml=xml), tempfile.TemporaryDirectory() as directory:
                source = self.archive(directory, xml, xml)
                before = source.read_bytes()
                with SafeGx3Archive(source) as archive:
                    self.assertEqual(detect(archive).decision.value, "SUPPORTED")
                    self.assertEqual(discover_project(archive)["cpu"], "FX5U")
                self.assertEqual(source.read_bytes(), before)

    def test_ambiguous_nodes_and_locations(self):
        supported = '<Config Unit="FX5U" UnitId="528"/>'
        other = '<Config Unit="R04" UnitId="4097"/>'
        cases = [f"<Root>{supported}{other}</Root>", f"<Root>{other}{supported}</Root>",
                 f"<Root>{supported}{supported}</Root>", f"<Root>{supported}<Nested>{other}</Nested></Root>",
                 f"<Root><Nested>{other}</Nested>{supported}</Root>",
                 '<Config Unit="FX5U" UnitId="528">' + other + '</Config>',
                 f"<Root><Nested>{supported}</Nested></Root>", "<Root/>"]
        for xml in cases:
            with self.subTest(xml=xml), tempfile.TemporaryDirectory() as directory:
                source = self.archive(directory, xml, xml)
                before = source.read_bytes()
                with SafeGx3Archive(source) as archive:
                    self.assertEqual(detect(archive).decision.value, "AMBIGUOUS")
                    with self.assertRaises(ValueError):
                        discover_project(archive)
                report = inspect(source)
                self.assertEqual(report["profile"]["decision"], "AMBIGUOUS")
                self.assertIsNone(report["project"])
                ir = build_neutral_ir(source)
                self.assertEqual(ir["profile"]["detector_status"], "AMBIGUOUS")
                self.assertEqual(ir["profile"]["cpu_ui_selection"], "MINING_REQUIRED")
                self.assertEqual(ir["pous"], [])
                self.assertEqual(ir["coverage"]["project"], {"total": 1, "decoded": 0, "partial": 1, "unknown": 0})
                self.assertEqual(ir["findings"][0]["reason"], report["profile"]["findings"][0]["reason"])
                self.assertEqual(source.read_bytes(), before)

    def test_dual_file_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.archive(directory, '<Config Unit="FX5U" UnitId="528"/>', '<Config Unit="R04" UnitId="4097"/>')
            with SafeGx3Archive(source) as archive:
                self.assertEqual(detect(archive).decision.value, "AMBIGUOUS")
                with self.assertRaises(ValueError):
                    discover_project(archive)
            ir = build_neutral_ir(source)
            self.assertEqual(ir["profile"]["detector_status"], "AMBIGUOUS")
            self.assertEqual(ir["findings"][0]["reason"], "dual Config evidence differs")

    def test_single_unsupported_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            with SafeGx3Archive(self.archive(directory, '<Root><Config Unit="R04" UnitId="4097"/></Root>')) as archive:
                self.assertEqual(detect(archive).decision.value, "UNSUPPORTED")

    def test_conflicting_evidence_is_order_independent(self):
        nodes = ['<Config Unit="FX5U" UnitId="528"/>', '<Config Unit="R04" UnitId="4097"/>']
        reasons = []
        for ordered in (nodes, nodes[::-1]):
            with tempfile.TemporaryDirectory() as directory:
                with SafeGx3Archive(self.archive(directory, '<Root>' + ''.join(ordered) + '</Root>')) as archive:
                    reasons.append(detect(archive).findings[0].reason)
        self.assertEqual(reasons[0], reasons[1])
        self.assertIn("('FX5U', '528')", reasons[0])
        self.assertIn("('R04', '4097')", reasons[0])
