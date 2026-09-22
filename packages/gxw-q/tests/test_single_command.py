"""Installed-only synthetic checks for the strict single-command resolver."""
from __future__ import annotations

import importlib
import os
import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import olefile
import pythoncom
from win32com import storagecon

SC = importlib.import_module("gxw_single_command")
W = importlib.import_module("gxw_ladder_writer")
OLD = b"\x03\x00\x03\x04\x90\x01\x04"  # LD M1
NEW = b"\x03\x00\x03\x04\x90\x02\x04"  # LD M2
END = b"\x04\x34\x02\x04"


def cfb(path: Path, streams: dict[str, bytes]) -> bytes:
    flags = storagecon.STGM_CREATE | storagecon.STGM_READWRITE | storagecon.STGM_SHARE_EXCLUSIVE
    storage = pythoncom.StgCreateDocfile(str(path), flags, 0)
    try:
        for name, data in streams.items():
            stream = storage.CreateStream(name, W.CREATE, 0, 0)
            stream.Write(data)
            stream = None
        storage.Commit(0)
    finally:
        storage = None
    return path.read_bytes()


def res(name: str, first: bytes, second: bytes | None) -> bytes:
    # The source display-name field is independently allowed to be NUL-only;
    # the XML/trailer POU name is the authoritative role identity.
    n, start = 1, 56 + 2
    head = struct.pack("<I", n) + b"\0\0"
    head += b"\0" * (start - 4 - len(head)) + struct.pack("<I", len(first))
    second = b"" if second is None else second
    tail = (b"\0" * 8 + struct.pack("<I", 1) + struct.pack("<I", len(name) + 1)
            + name.encode("utf-16le") + b"\0\0" + struct.pack("<II", 4, 1))
    return head + first + b"\0" * 8 + struct.pack("<I", len(second)) + second + tail


def prg(name: str, payload: bytes) -> bytes:
    n, start = 1, 77 + 2
    head = struct.pack("<I", n) + b"\0\0"
    head += b"\0" * (start - 24 - len(head))
    lengths = struct.pack("<II", len(payload) + 20, len(payload) + 20)
    return head + lengths + SC.ANCHOR + payload + b"\0" * 24


def project(root: Path, first: bytes, second: bytes | None = None, prg_payload: bytes | None = None,
            entries: list[tuple[str, str]] | None = None, extra: dict[str, bytes] | None = None) -> Path:
    root.mkdir(exist_ok=True)
    name = "P1"
    sub = {"1": res(name, first, second), "2": prg(name, prg_payload or first)}
    sub.update(extra or {})
    hdb = cfb(root / "hdb.ole", sub)
    entries = entries or [("P1.res", "1"), ("P1.Program.pou", "2")]
    xml = "<root>" + "".join(
        f"<D_Projectdata><szName>{n}</szName><iID>{i}</iID></D_Projectdata>" for n, i in entries
    ) + "</root>"
    source = root / "input.gxw"
    cfb(source, {"projectdatalist.xml": xml.encode(), "_hdb": hdb, "untouched": b"preserve"})
    return source


class StrictSingleCommandTests(unittest.TestCase):
    def resolve(self, source: Path):
        hdb = W.read_top(source, "_hdb")
        return SC.resolve(source, W.hdb_substreams(hdb), OLD, hdb)

    def test_real_cfb_resolver_accepts_three_identical_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.resolve(project(Path(tmp), OLD + END, OLD + END))
            self.assertEqual(3, len(target.offsets))

    def test_empty_second_payload_is_a_two_copy_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.resolve(project(Path(tmp), OLD + END))
            self.assertEqual(2, len(target.offsets))

    def test_empty_display_header_with_xml_and_trailer_name_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.resolve(project(Path(tmp), OLD + END))
            self.assertEqual("P1", target.name)

    def test_divergence_malformed_lengths_and_trailer_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            with self.assertRaises(SC.Rejected):
                self.resolve(project(root / "different", payload, NEW + END))
            broken = bytearray(res("P1", payload, None)); struct.pack_into("<I", broken, 56, 999)
            with self.assertRaises(SC.Rejected):
                SC.parse_res("1", bytes(broken), "P1")
            invalid = bytearray(res("P1", payload, None)); invalid[-1] ^= 1
            with self.assertRaises(SC.Rejected):
                SC.parse_res("1", bytes(invalid), "P1")

    def test_xml_duplicate_role_shared_id_and_missing_role_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            variants = (
                [("P1.res", "1"), ("P1.res", "3"), ("P1.Program.pou", "2")],
                [("P1.res", "1"), ("P1.Program.pou", "1")],
                [("P1.res", "1")],
            )
            for index, entries in enumerate(variants):
                with self.assertRaises(SC.Rejected):
                    self.resolve(project(root / str(index), payload, entries=entries))

    def test_embedded_partial_and_extra_old_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            with self.assertRaises(SC.Rejected):
                self.resolve(project(root / "extra", payload, extra={"9": b"metadata" + OLD}))
            self.assertEqual(10, SC.apply(project(root / "partial", OLD[:-1] + END), OLD, NEW, False, None, True))
            self.assertEqual(10, SC.apply(project(root / "repeated", OLD + OLD + END, OLD + OLD + END), OLD, NEW, False, None, True))

    def test_metadata_free_fixture_remains_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hdb = cfb(root / "hdb.ole", {"1": res("P1", OLD + END, None), "2": prg("P1", OLD + END)})
            source = root / "metadata-free.gxw"
            cfb(source, {"_hdb": hdb})
            self.assertEqual(10, SC.apply(source, OLD, NEW, False, root / "out.gxw", False))

    def test_equal_length_and_supported_new_are_required_even_with_collision_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = project(Path(tmp), OLD + END)
            self.assertEqual(10, SC.apply(source, OLD, NEW + b"\0", False, None, True))
            self.assertEqual(10, SC.apply(source, OLD, b"\x05\x40\x01\x7f\x05", False, None, True))

    def test_actual_com_apply_preserves_top_bytes_refuses_clobber_and_cleans_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            source, output = project(root, payload, payload), root / "out.gxw"
            with mock.patch.object(W, "self_check", return_value=(0, "ok")):
                self.assertEqual(0, W.do_replace(source, OLD, NEW, True, False, output, False, False))
            ole = olefile.OleFileIO(output)
            try:
                self.assertEqual(b"preserve", ole.openstream("untouched").read())
            finally:
                ole.close()
            with mock.patch.object(W, "self_check", return_value=(0, "ok")):
                self.assertEqual(9, SC.apply(source, OLD, NEW, False, output, False))
            failed = root / "failed.gxw"
            with mock.patch.object(W, "self_check", return_value=(7, "failed")):
                self.assertEqual(9, SC.apply(source, OLD, NEW, False, failed, False))
            self.assertFalse(failed.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_unrelated_pou_without_old_is_preserved_without_body_grammar_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            source, output = project(
                root, payload, payload,
                entries=[("P1.res", "1"), ("P1.Program.pou", "2"), ("P2.res", "3"), ("P2.Program.pou", "4")],
                extra={"3": b"unsupported-res", "4": b"divergent-prg"},
            ), root / "out.gxw"
            before = W.hdb_substreams(W.read_top(source, "_hdb"))
            with mock.patch.object(W, "self_check", return_value=(0, "ok")):
                self.assertEqual(0, W.do_replace(source, OLD, NEW, True, False, output, False, False))
            after = W.hdb_substreams(W.read_top(output, "_hdb"))
            self.assertEqual(before["3"], after["3"])
            self.assertEqual(before["4"], after["4"])

    def test_two_independently_valid_pous_with_old_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            source = project(
                root, payload, payload,
                entries=[("P1.res", "1"), ("P1.Program.pou", "2"), ("P2.res", "3"), ("P2.Program.pou", "4")],
                extra={"3": res("P2", payload, payload), "4": prg("P2", payload)},
            )
            output = root / "out.gxw"
            self.assertEqual(10, W.do_replace(source, OLD, NEW, True, False, output, False, False))
            self.assertFalse(output.exists())

    def test_embedded_old_inside_a_valid_operand_is_not_a_logical_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, old, new = Path(tmp), b"\x03\x14\x03", b"\x03\x18\x03"
            command = b"\x03\x00\x03" + b"\x07\xa8" + old + b"\0\x07"
            source, output = project(root, command + END), root / "out.gxw"
            self.assertEqual(10, W.do_replace(source, old, new, True, False, output, False, False))
            self.assertFalse(output.exists())

    def test_modifier_and_arbitrary_05_arity_class_are_rejected(self):
        modifier = b"\x03\x00\x03\x04\xf0\x01\x04\x04\x90\x01\x04"
        arbitrary_a = b"\x05\x4c\x7f\x00\x05\x04\x90\x01\x04\x04\xa8\x01\x04"
        for value in (modifier, arbitrary_a):
            with self.assertRaises(SC.Rejected):
                SC.exact_command(value)

    def test_length_consumed_title_and_note_grammar_reject_old_search_shapes(self):
        title = b"\x09\x80\x05TITLE\x09"
        with tempfile.TemporaryDirectory() as tmp:
            target = self.resolve(project(Path(tmp), title + OLD + END))
            self.assertEqual(2, len(target.offsets))
        bad_title_header = b"\x09\x80\x04TITLE\x09" + END
        bad_title_close = b"\x09\x80\x05TITLE\x08" + END
        bad_note_header = b"\x09\x82\x04NOTE!\x09" + END
        legacy_search_shape = b"\x0e\xeeTITLE\x0e\x04\xa8\x00" + END
        for payload in (bad_title_header, bad_title_close, bad_note_header, legacy_search_shape):
            with self.assertRaises(SC.Rejected):
                SC.parse_payload("1", 0, payload)

    def test_constant_frame_widths_and_extended_modifier_reject(self):
        prefix = b"\x03\x00\x03"
        valid_32 = prefix + b"\x07\xe9\x01\x00\x00\x00\x07"
        too_wide_16 = prefix + b"\x06\xe8\x01\x00\x00\x06"
        short_float = prefix + b"\x06\xec\x01\x00\x00\x06"
        extended_modifier = prefix + b"\x07\xf0\x01\x00\x00\x00\x07\x04\x90\x01\x04"
        SC.exact_command(valid_32)
        for value in (too_wide_16, short_float, extended_modifier):
            with self.assertRaises(SC.Rejected):
                SC.exact_command(value)

    def test_real_cli_apply_runs_real_self_check_and_reopens_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, payload = Path(tmp), OLD + END
            source, output = project(root, payload), root / "out.gxw"
            executable = Path(sys.executable).with_name("gxw-write.exe")
            environment = dict(os.environ, PYTHONUTF8="1")
            result = subprocess.run(
                [str(executable), str(source), "--replace", OLD.hex(), NEW.hex(), "--apply", "--out", str(output)],
                capture_output=True, timeout=30, env=environment,
            )
            evidence = (result.stdout + result.stderr).decode("utf-8", errors="replace")
            self.assertEqual(0, result.returncode, evidence)
            self.assertTrue(output.is_file())
            rewritten = W.hdb_substreams(W.read_top(output, "_hdb"))
            self.assertIn(NEW + END, rewritten["1"])
            self.assertIn(NEW + END, rewritten["2"])


if __name__ == "__main__":
    unittest.main()
