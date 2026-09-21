import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("public_build", Path(__file__).resolve().parents[1] / "build_artifacts.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

class BuildBoundaryTests(unittest.TestCase):
    def test_git_override_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(os.environ, {"GIT_DIR": str(root)}), self.assertRaises(ValueError):
                builder.build(root, root / "output")
            self.assertFalse((root / "output").exists())

    def test_missing_independent_git_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                builder.build(root, root / "output")
            self.assertFalse((root / "output").exists())

    def test_dirty_source_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            with mock.patch.object(builder, "git", side_effect=[str(root).encode(), b" M module.py\n"]), self.assertRaises(ValueError):
                builder.build(root, root / "output")
            self.assertFalse((root / "output").exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "source"
            (root / ".git").mkdir(parents=True)
            output = parent / "output"
            output.mkdir()
            marker = output / "marker.txt"
            marker.write_bytes(b"retain")
            with mock.patch.object(builder, "git", side_effect=[str(root).encode(), b""]), self.assertRaises(ValueError):
                builder.build(root, output)
            self.assertEqual(marker.read_bytes(), b"retain")

if __name__ == "__main__":
    unittest.main()
