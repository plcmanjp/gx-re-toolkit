"""Synthetic fail-closed checks for GXW replacement and CSV publication."""

from __future__ import annotations

import io
import ctypes
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import gxw_ladder_reader as READER
import gxw_ladder_writer as WRITER


class EmptyOldTests(unittest.TestCase):
    def test_empty_old_is_rejected_before_reading_or_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gxw"
            output = Path(directory) / "output.gxw"
            source.write_bytes(b"source bytes")
            with mock.patch.object(WRITER, "read_top", side_effect=AssertionError("must not read")):
                self.assertEqual(7, WRITER.do_replace(source, b"", b"NEW", True, False, output, True, False))
                self.assertEqual(7, WRITER.do_replace(source, b"", b"", False, False, output, False, False))
            self.assertEqual(b"source bytes", source.read_bytes())
            self.assertFalse(output.exists())

    def test_cli_rejects_empty_old_with_optimizations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gxw"
            output = Path(directory) / "output.gxw"
            source.write_bytes(b"source bytes")
            for flags, optimize in (([], None), (["-O"], None), ([], "1"), ([], "2")):
                with self.subTest(flags=flags, optimize=optimize):
                    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
                    if optimize is None:
                        environment.pop("PYTHONOPTIMIZE", None)
                    else:
                        environment["PYTHONOPTIMIZE"] = optimize
                    result = subprocess.run(
                        [sys.executable, *flags, "-m", "gxw_ladder_writer", str(source),
                         "--replace", "", "4e4557", "--apply", "--all", "--out", str(output)],
                        cwd=directory, env=environment, capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(7, result.returncode, result.stderr)
                    self.assertIn("OLD 빈 패턴", result.stdout)
                    self.assertEqual(b"source bytes", source.read_bytes())
                    self.assertFalse(output.exists())


class CsvPublicationTests(unittest.TestCase):
    @staticmethod
    def publish(source: Path, target: Path, names: tuple[str, ...] = ("MAIN",), render=None) -> None:
        pous = {name: (0, b"synthetic", None) for name in names}
        render = render or (lambda name, *_: name + "\r\n")
        with (mock.patch.object(sys, "argv", ["gxw-inspect", str(source), "--csv", str(target)]),
              mock.patch.object(READER, "project_info", return_value=("PROJECT", "PLC")),
              mock.patch.object(READER, "pou_rows", return_value=([], set(), set())),
              mock.patch.object(READER, "typed_note_records", return_value=()),
              mock.patch.object(READER, "gx_csv_for_pou", side_effect=render)):
            READER.output_csv(str(source), pous, {"X10": "synthetic comment"})

    def test_new_directory_publishes_utf16_and_rerun_preserves_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gxw"
            target = Path(directory) / "output"
            source.write_bytes(b"source bytes")
            self.publish(source, target)
            published = {p.name: p.read_bytes() for p in target.iterdir()}
            self.assertEqual({"MAIN.csv", "COMMENT.csv"}, set(published))
            self.assertTrue(all(body.startswith(b"\xff\xfe") for body in published.values()))
            with self.assertRaises(FileExistsError):
                self.publish(source, target)
            self.assertEqual(published, {p.name: p.read_bytes() for p in target.iterdir()})
            self.assertEqual(b"source bytes", source.read_bytes())

    def test_name_collisions_and_unsafe_names_create_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gxw"
            source.write_bytes(b"source bytes")
            for names in (("COMMENT",), ("MAIN", "main"), ("../outside",), ("CON",)):
                target = Path(directory) / "output"
                with self.subTest(names=names), self.assertRaises(ValueError):
                    self.publish(source, target, names)
                self.assertFalse(target.exists())
                self.assertFalse(list(Path(directory).glob(".gxw-csv-*")))

    def test_generation_or_rename_failure_preserves_other_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gxw"
            sibling = Path(directory) / "existing.csv"
            target = Path(directory) / "output"
            source.write_bytes(b"source bytes")
            sibling.write_bytes(b"existing bytes")
            with self.assertRaisesRegex(RuntimeError, "render failed"):
                self.publish(source, target, render=mock.Mock(side_effect=RuntimeError("render failed")))
            self.assertFalse(target.exists())
            with mock.patch.object(READER.os, "rename", side_effect=RuntimeError("rename failed")):
                with self.assertRaisesRegex(RuntimeError, "rename failed"):
                    self.publish(source, target)
            with mock.patch.object(READER.os, "rename", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    self.publish(source, target)
            self.assertFalse(target.exists())
            self.assertFalse(list(Path(directory).glob(".gxw-csv-*")))
            self.assertEqual(b"source bytes", source.read_bytes())
            self.assertEqual(b"existing bytes", sibling.read_bytes())

    def test_linux_no_replace_preserves_destination_created_at_publish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged, target = root / "candidate", root / "output"
            staged.mkdir()
            (staged / "MAIN.csv").write_bytes(b"candidate")
            class Rename:
                argtypes = None
                restype = None
                def __call__(self, source_fd, source, target_fd, destination, flags):
                    self_test.assertEqual((-100, -100, 1), (source_fd, target_fd, flags))
                    target.mkdir()
                    (target / "other.txt").write_bytes(b"other owner's file")
                    ctypes.set_errno(errno.EEXIST)
                    return -1
            self_test = self
            linux_os = SimpleNamespace(name="posix", fsencode=os.fsencode, strerror=os.strerror)
            with (mock.patch.object(READER, "os", linux_os),
                  mock.patch.object(READER.sys, "platform", "linux"),
                  mock.patch("ctypes.CDLL", return_value=SimpleNamespace(renameat2=Rename()))):
                with self.assertRaises(FileExistsError):
                    READER._publish_csv_directory(target, staged)
            self.assertEqual(b"other owner's file", (target / "other.txt").read_bytes())
            self.assertEqual(b"candidate", (staged / "MAIN.csv").read_bytes())

    def test_stdout_mode_keeps_text_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gxw"
            stream = io.StringIO()
            with (mock.patch.object(sys, "argv", ["gxw-inspect", str(source), "--csv"]),
                  mock.patch.object(READER, "project_info", return_value=("PROJECT", "PLC")),
                  mock.patch.object(READER, "pou_rows", return_value=([], set(), set())),
                  mock.patch.object(READER, "typed_note_records", return_value=()),
                  mock.patch.object(READER, "gx_csv_for_pou", return_value="synthetic\r\n"),
                  mock.patch.object(sys, "stdout", stream)):
                READER.output_csv(str(source), {"MAIN": (0, b"synthetic", None)}, {})
            self.assertEqual("synthetic\r\n", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
