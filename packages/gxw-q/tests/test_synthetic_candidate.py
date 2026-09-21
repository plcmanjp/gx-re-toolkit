"""Installed-only checks for the isolated encoder adapter."""
from __future__ import annotations

import importlib
from pathlib import Path
import site
import tempfile
import unittest
from unittest import mock


ENCODER = importlib.import_module("wt9_fill_pou_body")


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


if __name__ == "__main__":
    unittest.main()
