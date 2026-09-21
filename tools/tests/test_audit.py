import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("public_audit", Path(__file__).resolve().parents[1] / "audit_public_tree.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

class AuditTests(unittest.TestCase):
    def test_rejects_binary_and_traversal(self):
        self.assertTrue(audit.inspect("sample.gx3", b"binary"))
        self.assertTrue(audit.inspect("../outside.py", b"x = 1\n"))

    def test_accepts_synthetic_python(self):
        self.assertEqual(audit.inspect("src/example.py", b"x = 1\n"), [])

    def test_duplicate_archive_member_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("a.py", "x = 1\n")
                archive.writestr("a.py", "x = 2\n")
            with self.assertRaises(ValueError):
                list(audit.archive_entries(path))

if __name__ == "__main__":
    unittest.main()
