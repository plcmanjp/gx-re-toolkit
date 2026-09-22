"""Installed-only checks for the isolated encoder adapter."""
from __future__ import annotations

import hashlib
import importlib
import io
from pathlib import Path
import site
import subprocess
import struct
import tempfile
import unittest
from unittest import mock

import olefile
import pythoncom
from win32com import storagecon


ENCODER = importlib.import_module("wt9_fill_pou_body")
WRITER = importlib.import_module("gxw_ladder_writer")


class EncoderSyntheticTests(unittest.TestCase):
    def test_encoder_is_installed_and_keeps_known_binary_constant(self) -> None:
        roots = [Path(value).resolve() for value in site.getsitepackages()]
        self.assertTrue(any(Path(ENCODER.__file__).resolve().is_relative_to(root) for root in roots))
        self.assertEqual((0x4C, 0x02, 0x00), ENCODER.PREFIX_05["MOV"])

    def test_temporary_ole_path_is_cleaned_after_success_and_exception(self) -> None:
        created: list[Path] = []
        def successful(hdb, replacements, path):
            created.append(path)
            path.write_bytes(b"synthetic")
            return b"patched"
        with mock.patch.object(ENCODER.W, "patch_hdb_substreams", successful):
            self.assertEqual(b"patched", ENCODER._patch_hdb_with_temporary(b"hdb", {}, "gxw-test-"))
        self.assertFalse(created[0].parent.exists())
        def failing(hdb, replacements, path):
            created.append(path)
            path.write_bytes(b"synthetic")
            raise RuntimeError("storage failure")
        with mock.patch.object(ENCODER.W, "patch_hdb_substreams", failing):
            with self.assertRaisesRegex(RuntimeError, "storage failure"):
                ENCODER._patch_hdb_with_temporary(b"hdb", {}, "gxw-test-")
        self.assertFalse(created[1].parent.exists())

    def test_storage_exception_releases_stream_and_storage_before_temp_cleanup(self) -> None:
        released: list[str] = []
        class Stream:
            def Write(self, data):
                raise RuntimeError("storage failure")
            def __del__(self):
                released.append("stream")
        class Storage:
            def CreateStream(self, *args):
                return Stream()
            def __del__(self):
                released.append("storage")
        class PythonCom:
            @staticmethod
            def StgOpenStorage(*args):
                return Storage()
        with mock.patch.object(ENCODER.W, "pythoncom", PythonCom):
            with self.assertRaisesRegex(RuntimeError, "storage failure"):
                ENCODER._patch_hdb_with_temporary(b"hdb", {"item": b"body"}, "gxw-test-")
        self.assertEqual({"stream", "storage"}, set(released))

    def test_direct_patch_exception_removes_its_child_file(self) -> None:
        class PythonCom:
            @staticmethod
            def StgOpenStorage(*args):
                raise RuntimeError("open failure")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "work.ole"
            with mock.patch.object(ENCODER.W, "pythoncom", PythonCom):
                with self.assertRaisesRegex(RuntimeError, "open failure"):
                    ENCODER.W.patch_hdb_substreams(b"hdb", {}, path)
            self.assertFalse(path.exists())

    def test_integer_and_modifier_overflow_are_rejected_before_masking(self) -> None:
        rejected = (
            lambda: WRITER.encode_operand("K4294967296"),
            lambda: ENCODER._enc_operand("K65536", False),
            lambda: ENCODER._enc_operand("K4294967296", True),
            lambda: ENCODER._enc_cmp_operand("K65536", False),
            lambda: ENCODER._mod_frame(ENCODER.MOD_ZINDEX, 256),
        )
        for encode in rejected:
            with self.assertRaises(ValueError):
                encode()
        for encode in (
            lambda: ENCODER._enc_operand("K-32769", False),
            lambda: ENCODER._enc_operand("K-2147483649", True),
            lambda: ENCODER._enc_operand("H10000", False),
            lambda: ENCODER._enc_operand("H100000000", True),
            lambda: ENCODER._mod_frame(ENCODER.MOD_ZINDEX, -1),
        ):
            with self.assertRaises(ValueError):
                encode()
        self.assertEqual("07e90000010007", WRITER.encode_operand("K65536").hex())
        self.assertEqual("07e90000008007", WRITER.encode_operand("K-2147483648").hex())
        self.assertEqual("07e9ffffffff07", WRITER.encode_operand("K4294967295").hex())
        self.assertEqual("05e8ffff05", WRITER.encode_operand("K-1").hex())
        self.assertEqual("07e9ffffffff07", ENCODER._enc_operand("K-1", True).hex())
        self.assertEqual("05e8008005", ENCODER._enc_operand("K-32768", False).hex())
        self.assertEqual("05eaffff05", ENCODER._enc_operand("HFFFF", False).hex())
        self.assertEqual("07ebffffffff07", ENCODER._enc_operand("HFFFFFFFF", True).hex())
        self.assertEqual("04f0ff04", ENCODER._mod_frame(ENCODER.MOD_ZINDEX, 255).hex())

    def test_failed_self_check_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            with (
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", return_value=(7, "failed")),
            ):
                self.assertEqual(9, WRITER.do_replace(source, old, new, True, False, output, True, True))
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))
            output.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                WRITER.prepare_candidate(source, output)
            self.assertEqual(b"existing", output.read_bytes())

    def test_single_command_apply_is_blocked_before_source_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            with mock.patch.object(WRITER, "read_top", side_effect=AssertionError("must not read")):
                self.assertEqual(10, WRITER.do_replace(source, b"OLD", b"NEW", True, False, output, False, True))
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_explicit_global_apply_remains_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            with (
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", return_value=(0, "ok")),
            ):
                self.assertEqual(0, WRITER.do_replace(source, old, new, True, False, output, True, True))
            self.assertEqual(b"source", output.read_bytes())

    def test_in_place_and_out_conflict_is_rejected_before_source_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            with mock.patch.object(WRITER, "read_top", side_effect=AssertionError("must not read")):
                self.assertEqual(8, WRITER.do_replace(source, b"OLD", b"NEW", True, True, output, True, True))
            self.assertEqual(b"source", source.read_bytes())
            self.assertFalse(output.exists())

    def test_snapshot_change_before_publish_preserves_source_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            original_hash = WRITER.source_sha256
            source_calls = 0
            def changing_hash(path):
                nonlocal source_calls
                if Path(path) == source:
                    source_calls += 1
                    if source_calls >= 4:
                        return "0" * 64
                return original_hash(path)
            with (
                mock.patch.object(WRITER, "source_sha256", side_effect=changing_hash),
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", return_value=(0, "ok")),
            ):
                self.assertEqual(9, WRITER.do_replace(source, old, new, True, False, output, True, True))
            self.assertEqual(b"source", source.read_bytes())
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_candidate_publish_rolls_back_destination_when_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            candidate, destination, backup = WRITER.prepare_candidate(source, output)
            self.assertIsNone(backup)
            original_unlink = Path.unlink
            failed_once = False
            def fail_candidate_unlink(path, *args, **kwargs):
                nonlocal failed_once
                if path == candidate and not failed_once:
                    failed_once = True
                    raise OSError("candidate unlink failed")
                return original_unlink(path, *args, **kwargs)
            with mock.patch.object(Path, "unlink", fail_candidate_unlink):
                with self.assertRaisesRegex(RuntimeError, "rollback"):
                    WRITER.publish_candidate(candidate, source, destination)
            self.assertFalse(destination.exists())
            WRITER.discard_candidate(candidate)
            self.assertFalse(candidate.exists())

    def test_in_place_replace_failure_removes_its_new_backup_and_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            with (
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", return_value=(0, "ok")),
                mock.patch.object(WRITER.os, "replace", side_effect=OSError("replace failed")),
            ):
                self.assertEqual(9, WRITER.do_replace(source, old, new, True, True, None, True, True))
            self.assertEqual(b"source", source.read_bytes())
            self.assertFalse(source.with_suffix(".gxw.bak").exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_nonstandard_self_check_exception_is_a_safe_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            with (
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", side_effect=LookupError("reader unavailable")),
            ):
                self.assertEqual(9, WRITER.do_replace(source, old, new, True, False, output, True, True))
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_timeout_self_check_is_a_safe_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            with (
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", side_effect=subprocess.TimeoutExpired(["reader"], 30)),
            ):
                self.assertEqual(9, WRITER.do_replace(source, old, new, True, False, output, True, True))
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_base_exception_still_cleans_its_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            old, new = b"OLD", b"NEW"
            with (
                mock.patch.object(WRITER, "read_top", return_value=old),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"s": old}),
                mock.patch.object(WRITER, "patch_hdb_substreams", return_value=b"patched"),
                mock.patch.object(WRITER, "write_top_hdb"),
                mock.patch.object(WRITER, "self_check", side_effect=KeyboardInterrupt),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    WRITER.do_replace(source, old, new, True, False, output, True, True)
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_actual_windows_cfb_candidate_is_published_without_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            flags = storagecon.STGM_CREATE | storagecon.STGM_READWRITE | storagecon.STGM_SHARE_EXCLUSIVE
            storage = pythoncom.StgCreateDocfile(str(source), flags, 0)
            stream = storage.CreateStream("history.xml", WRITER.CREATE, 0, 0)
            stream.Write(b"old")
            stream = None
            stream = storage.CreateStream("untouched", WRITER.CREATE, 0, 0)
            stream.Write(b"preserve")
            stream = None
            storage.Commit(0)
            storage = None
            source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            candidate, destination, backup = WRITER.prepare_candidate(source, output)
            self.assertIsNone(backup)
            WRITER.write_streams(candidate, {"history.xml": b"new"})
            WRITER.publish_candidate(candidate, source, destination)
            self.assertFalse(candidate.exists())
            archive = olefile.OleFileIO(output)
            try:
                self.assertEqual(b"new", archive.openstream("history.xml").read())
                self.assertEqual(b"preserve", archive.openstream("untouched").read())
            finally:
                archive.close()
            self.assertEqual(source_sha256, hashlib.sha256(source.read_bytes()).hexdigest())

    def test_encoder_publish_helper_rejects_failed_check_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            with (
                mock.patch.object(WRITER, "write_streams"),
                mock.patch.object(WRITER, "self_check", return_value=(7, "failed")),
            ):
                self.assertEqual((9, ""), ENCODER._write_check_publish(source, output, b"hdb", b"history"))
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob(".gxw-candidate-*")))
            output.write_bytes(b"existing")
            self.assertEqual((9, ""), ENCODER._write_check_publish(source, output, b"hdb", b"history"))
            self.assertEqual(b"existing", output.read_bytes())

    def test_fill_entry_dry_run_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.gxw", root / "output.gxw"
            source.write_bytes(b"source")
            with (
                mock.patch.object(WRITER, "read_top", return_value=b"hdb"),
                mock.patch.object(WRITER, "hdb_substreams", return_value={"res": b"res", "prg": b"prg"}),
                mock.patch.object(ENCODER, "pou_streams", return_value={"P1": {"res": "res", "prg": "prg"}}),
                mock.patch.object(ENCODER, "encode_il_body", return_value=b"IL"),
                mock.patch.object(ENCODER, "fill_res", return_value=b"new-res"),
                mock.patch.object(ENCODER, "fill_prg", return_value=b"new-prg"),
                mock.patch.object(WRITER, "write_streams", side_effect=AssertionError("must not write")),
            ):
                self.assertEqual(0, ENCODER.fill_pou(str(source), "P1", "LD M0", False, str(output)))
            self.assertFalse(output.exists())

    def test_fill_and_transpose_entries_reject_reader_failures_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.gxw"
            source.write_bytes(b"source")
            res = bytearray(96); marker = 80; res[marker:marker + 3] = b"\x34\x02\x04"; struct.pack_into("<I", res, 48, marker - 48 - 1)
            prg = bytearray(96); anchor = 8; prg[anchor:anchor + 16] = b"\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"; prg[40:43] = b"\x34\x02\x04"
            for name, invoke, streams in (
                ("fill", lambda out: ENCODER.fill_pou(str(source), "P1", "LD M0", True, str(out)), {"res": b"res", "prg": b"prg"}),
                ("transpose", lambda out: ENCODER.transpose_pou(str(source), "P1", {}, True, str(out)), {"res": bytes(res), "prg": bytes(prg)}),
            ):
                for failure in ((7, "failed"), subprocess.TimeoutExpired(["reader"], 30)):
                    output = root / f"{name}-{type(failure).__name__}.gxw"
                    with (
                        mock.patch.object(WRITER, "read_top", return_value=b"hdb"),
                        mock.patch.object(WRITER, "hdb_substreams", return_value=streams),
                        mock.patch.object(ENCODER, "pou_streams", return_value={"P1": {"res": "res", "prg": "prg"}}),
                        mock.patch.object(ENCODER, "encode_il_body", return_value=b"IL"),
                        mock.patch.object(ENCODER, "fill_res", return_value=b"new-res"),
                        mock.patch.object(ENCODER, "fill_prg", return_value=b"new-prg"),
                        mock.patch.object(ENCODER, "transpose_il_region", side_effect=lambda region, offsets: (region, [])),
                        mock.patch.object(ENCODER, "_patch_hdb_with_temporary", return_value=b"patched"),
                        mock.patch.object(ENCODER, "_history_with_stream_digests", return_value=b"history"),
                        mock.patch.object(WRITER, "write_streams"),
                        mock.patch.object(WRITER, "self_check", side_effect=failure if isinstance(failure, BaseException) else None, return_value=failure if isinstance(failure, tuple) else mock.DEFAULT),
                    ):
                        self.assertEqual(9, invoke(output))
                    self.assertFalse(output.exists())
                    self.assertFalse(list(root.glob(".gxw-candidate-*")))

    def test_transpose_rejects_32bit_address_overflow_before_candidate(self) -> None:
        with self.assertRaises(ValueError):
            ENCODER._enc_frame(0xA8, 0x100000000)
        with mock.patch.object(ENCODER, "collect_operands", return_value=[(0, 4, 0xA8, 0xFFFFFFFF, 4)]):
            with self.assertRaises(ValueError):
                ENCODER.transpose_il_region(b"body", {"D": 1})

    def test_transpose_cli_reports_address_overflow(self) -> None:
        with (
            mock.patch("sys.argv", ["gxw-encode", "input.gxw", "P1", "--transpose", "D:+1"]),
            mock.patch.object(ENCODER, "transpose_pou", side_effect=ValueError("32-bit frame range")),
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            self.assertEqual(2, ENCODER.main())
        self.assertIn("32-bit frame range", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
