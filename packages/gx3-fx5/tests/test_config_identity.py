"""Independent file-backed CPU identity regressions; no field acceptance."""
import hashlib
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

    def test_dual_file_title_only_difference_is_nuisance(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.archive(
                directory,
                '<Config Unit="FX5U" UnitId="528" Title="operator label"/>',
                '<Config Unit="FX5U" UnitId="528" Title=""/>',
            )
            before = source.read_bytes()
            with SafeGx3Archive(source) as archive:
                self.assertEqual(detect(archive).decision.value, "SUPPORTED")
                project = discover_project(archive)
                self.assertEqual(project["cpu"], "FX5U")
                self.assertEqual(project["title_digest"], hashlib.sha256(b"operator label").hexdigest())
            ir = build_neutral_ir(source)
            self.assertEqual(ir["profile"]["detector_status"], "SUPPORTED")
            self.assertEqual(source.read_bytes(), before)

    def assert_ambiguous_pair(self, primary, mirror):
        with tempfile.TemporaryDirectory() as directory:
            source = self.archive(directory, primary, mirror)
            before = source.read_bytes()
            with SafeGx3Archive(source) as archive:
                self.assertEqual(detect(archive).decision.value, "AMBIGUOUS")
                with self.assertRaises(ValueError):
                    discover_project(archive)
            ir = build_neutral_ir(source)
            self.assertEqual(ir["profile"]["detector_status"], "AMBIGUOUS")
            self.assertEqual(ir["pous"], [])
            self.assertEqual(source.read_bytes(), before)

    def test_wrapped_config_title_and_missing_title_are_nuisance(self):
        for mirrored_title in (' Title="mirror label"', ''):
            with self.subTest(mirrored_title=mirrored_title), tempfile.TemporaryDirectory() as directory:
                source = self.archive(
                    directory,
                    '<Root Title="wrapper"><Config Unit="FX5U" UnitId="528" Title="operator label"/></Root>',
                    '<Root Title="wrapper"><Config Unit="FX5U" UnitId="528"' + mirrored_title + '/></Root>',
                )
                before = source.read_bytes()
                with SafeGx3Archive(source) as archive:
                    self.assertEqual(detect(archive).decision.value, "SUPPORTED")
                    self.assertEqual(discover_project(archive)["title_digest"],
                                     hashlib.sha256(b"operator label").hexdigest())
                self.assertEqual(build_neutral_ir(source)["profile"]["detector_status"], "SUPPORTED")
                self.assertEqual(source.read_bytes(), before)

    def test_title_exception_is_exact_and_config_only(self):
        cases = (
            ('<Root Title="one"><Config Unit="FX5U" UnitId="528"/></Root>',
             '<Root Title="two"><Config Unit="FX5U" UnitId="528"/></Root>'),
            ('<Config Unit="FX5U" UnitId="528"><Child Title="one"/></Config>',
             '<Config Unit="FX5U" UnitId="528"><Child Title="two"/></Config>'),
            ('<Config Unit="FX5U" UnitId="528" title="one"/>',
             '<Config Unit="FX5U" UnitId="528" title="two"/>'),
            ('<Config xmlns:x="urn:synthetic" Unit="FX5U" UnitId="528" x:Title="one"/>',
             '<Config xmlns:x="urn:synthetic" Unit="FX5U" UnitId="528" x:Title="two"/>'),
        )
        for primary, mirror in cases:
            with self.subTest(primary=primary):
                self.assert_ambiguous_pair(primary, mirror)

    def test_text_tail_and_child_order_differences_remain_ambiguous(self):
        cases = (
            ('<Config Unit="FX5U" UnitId="528">one</Config>',
             '<Config Unit="FX5U" UnitId="528">two</Config>'),
            ('<Config Unit="FX5U" UnitId="528"><Child/>one</Config>',
             '<Config Unit="FX5U" UnitId="528"><Child/>two</Config>'),
            ('<Config Unit="FX5U" UnitId="528"><First/><Second/></Config>',
             '<Config Unit="FX5U" UnitId="528"><Second/><First/></Config>'),
        )
        for primary, mirror in cases:
            with self.subTest(primary=primary):
                self.assert_ambiguous_pair(primary, mirror)

    def test_attribute_order_is_not_semantic_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.archive(directory, '<Config Unit="FX5U" UnitId="528" Extra="same"/>',
                                  '<Config Extra="same" UnitId="528" Unit="FX5U"/>')
            before = source.read_bytes()
            with SafeGx3Archive(source) as archive:
                self.assertEqual(detect(archive).decision.value, "SUPPORTED")
            self.assertEqual(source.read_bytes(), before)

    def test_malformed_and_multiple_mirrors_remain_ambiguous(self):
        primary = '<Config Unit="FX5U" UnitId="528"/>'
        for mirror in ('<Config', '<!DOCTYPE Config [<!ENTITY x "one">]>' + primary):
            with self.subTest(mirror=mirror):
                self.assert_ambiguous_pair(primary, mirror)
        with tempfile.TemporaryDirectory() as directory:
            source = self.archive(directory, primary, primary)
            with ZipFile(source, "a") as archive:
                archive.writestr("!!CONFIG.XML", primary)
            before = source.read_bytes()
            with self.assertRaisesRegex(ValueError, "duplicate or case-fold-colliding paths"):
                SafeGx3Archive(source)
            self.assertEqual(source.read_bytes(), before)

    def test_title_difference_does_not_hide_config_count_or_location(self):
        for primary in ('<Root><Config Unit="FX5U" UnitId="528" Title="one"/>'
                        '<Config Unit="FX5U" UnitId="528" Title="one"/></Root>',
                        '<Root><Nested><Config Unit="FX5U" UnitId="528" Title="one"/></Nested></Root>'):
            with self.subTest(primary=primary):
                self.assert_ambiguous_pair(primary, primary.replace('Title="one"', 'Title="two"'))

    def test_comments_and_processing_instructions_are_not_ignored(self):
        config = '<Config Unit="FX5U" UnitId="528"/>'
        cases = (
            ('<Config Unit="FX5U" UnitId="528"><!--one--></Config>',
             '<Config Unit="FX5U" UnitId="528"><!--two--></Config>'),
            ('<Config Unit="FX5U" UnitId="528"><?mode one?></Config>',
             '<Config Unit="FX5U" UnitId="528"><?mode two?></Config>'),
            ('<?mode one?>' + config, '<?mode two?>' + config),
            (config + '<!--one-->', config + '<!--two-->'),
            ('<!--same-->' + config, config + '<!--same-->'),
            ('<?mode same?>' + config, config + '<?mode same?>'),
            ('<Config Unit="FX5U" UnitId="528" Title="one"><!--same--></Config>',
             '<Config Unit="FX5U" UnitId="528" Title="two"><!--same--></Config>'),
        )
        for primary, mirror in cases:
            with self.subTest(primary=primary):
                self.assert_ambiguous_pair(primary, mirror)

    def test_identical_non_element_metadata_retains_existing_acceptance(self):
        for xml in ('<?mode one?><Config Unit="FX5U" UnitId="528"><!--same--></Config>',
                    '<!--same--><Config Unit="FX5U" UnitId="528"/><?mode one?>'):
            with self.subTest(xml=xml), tempfile.TemporaryDirectory() as directory:
                source = self.archive(directory, xml, xml)
                before = source.read_bytes()
                with SafeGx3Archive(source) as archive:
                    self.assertEqual(detect(archive).decision.value, "SUPPORTED")
                self.assertEqual(source.read_bytes(), before)

    def test_declaration_identity_and_supported_title_exception(self):
        declaration = '<?xml version="1.0" encoding="UTF-8"?>'
        primary = declaration + '<Config Unit="FX5U" UnitId="528" Title="operator label"/>'
        for mirror in ('<?xml version="1.1" encoding="UTF-8"?><Config Unit="FX5U" UnitId="528"/>',
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Config Unit="FX5U" UnitId="528"/>',
                       '<Config Unit="FX5U" UnitId="528"/>'):
            with self.subTest(mirror=mirror):
                self.assert_ambiguous_pair(primary, mirror)
        with tempfile.TemporaryDirectory() as directory:
            source = self.archive(directory, primary, declaration + '<Config Unit="FX5U" UnitId="528"/>')
            before = source.read_bytes()
            with SafeGx3Archive(source) as archive:
                self.assertEqual(detect(archive).decision.value, "SUPPORTED")
                self.assertEqual(discover_project(archive)["title_digest"],
                                 hashlib.sha256(b"operator label").hexdigest())
            self.assertEqual(source.read_bytes(), before)

    def test_dual_file_non_title_difference_remains_ambiguous(self):
        cases = (
            ('<Config Unit="FX5U" UnitId="528" Extra="one"/>',
             '<Config Unit="FX5U" UnitId="528" Extra="two"/>'),
            ('<Config Unit="FX5U" UnitId="528"><Child/></Config>',
             '<Config Unit="FX5U" UnitId="528"/>'),
        )
        for primary, mirror in cases:
            with self.subTest(primary=primary), tempfile.TemporaryDirectory() as directory:
                source = self.archive(directory, primary, mirror)
                with SafeGx3Archive(source) as archive:
                    self.assertEqual(detect(archive).decision.value, "AMBIGUOUS")

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
