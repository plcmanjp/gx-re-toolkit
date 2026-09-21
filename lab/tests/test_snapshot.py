"""Synthetic snapshot safety checks; no engineering-software or private inputs."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gx_re_lab import snapshot


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "input.bin"
        self.path.write_bytes(b"synthetic input")

    def test_retains_exact_bytes_hash_and_closes_once(self):
        retained = snapshot._open_input_snapshot(self.path)
        descriptor = retained.descriptor
        self.assertEqual(b"synthetic input", retained.body)
        self.assertEqual(hashlib.sha256(retained.body).hexdigest(), retained.sha256)
        retained.verify()
        retained.close()
        retained.close()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_byte_cap(self):
        with patch.object(snapshot, "MAX_ARCHIVE_BYTES", 3):
            with self.assertRaises(snapshot.ConversionError):
                snapshot._open_input_snapshot(self.path)

    def test_open_handle_growth_is_bounded_to_cap_plus_one(self):
        actual_read = os.read
        requests = []
        def growing_read(descriptor, count):
            requests.append(count)
            return b"x" * count
        self.path.write_bytes(b"x")
        with patch.object(snapshot, "MAX_ARCHIVE_BYTES", 3), patch.object(snapshot.os, "read", side_effect=growing_read):
            with self.assertRaises(snapshot.ConversionError):
                snapshot._open_input_snapshot(self.path)
        self.assertEqual([4], requests)

    def test_changed_input_rejected(self):
        retained = snapshot._open_input_snapshot(self.path)
        self.addCleanup(retained.close)
        self.path.write_bytes(b"changed length")
        with self.assertRaises(RuntimeError):
            retained.verify()

    def test_replaced_path_identity_rejected(self):
        retained = snapshot._open_input_snapshot(self.path)
        self.addCleanup(retained.close)
        # Mock the path identity only: deterministic on Windows retained handles.
        actual_stat = os.stat
        other = self.path.with_name("other.bin")
        other.write_bytes(b"other identity")
        def swapped(path, *args, **kwargs):
            return actual_stat(other if Path(path) == self.path else path, *args, **kwargs)
        with patch.object(snapshot.os, "stat", side_effect=swapped):
            with self.assertRaises(RuntimeError):
                retained.verify()

    def test_link_ancestor_rejected_without_privileged_symlink_creation(self):
        original = snapshot._is_link_like
        with patch.object(snapshot, "_is_link_like", side_effect=lambda path: path == self.path.parent or original(path)):
            with self.assertRaises(snapshot.ConversionError):
                snapshot._open_input_snapshot(self.path)

    def test_mismatched_final_path_closes_descriptor(self):
        opened = []
        original = os.open
        def recording_open(*args, **kwargs):
            descriptor = original(*args, **kwargs)
            opened.append(descriptor)
            return descriptor
        with patch.object(snapshot.os, "open", side_effect=recording_open), patch.object(snapshot, "_handle_final_path", return_value="different"):
            with self.assertRaises(snapshot.ConversionError):
                snapshot._open_input_snapshot(self.path)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_directory_rejected(self):
        with self.assertRaises((OSError, snapshot.ConversionError)):
            snapshot._open_input_snapshot(self.path.parent)


if __name__ == "__main__":
    unittest.main()
