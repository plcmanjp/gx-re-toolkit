"""Synthetic cross-project identity and corpus boundary regressions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gx_re_lab import corpus_census as module
from gx_re_lab.lab import LabError


class CorpusCensusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.body = b"synthetic source, no project authority"
        (self.root / "a.gx3").write_bytes(self.body)
        (self.root / "b.gxw").write_bytes(self.body)
        self.case = {"case_id": "A", "path": "a.gx3", "adapter": "GX3-FX5",
                     "byte_count": len(self.body), "sha256": hashlib.sha256(self.body).hexdigest()}
        self.manifest = {"format": module.FORMAT, "version": 1, "cases": [self.case]}

    def observation(self, pin="a" * 64):
        return {"counts": {"pous": 1, "files": 1},
                "container_entries": [{"entry": "same-internal-key", "sha256": pin}]}

    def run_census(self, side_effect=None):
        with patch.dict(module.ADAPTERS, {"GX3-FX5": side_effect or (lambda *_: self.observation())}):
            return module.corpus_census(self.manifest, self.root)

    def test_duplicate_input_occurrences_are_individually_checked(self):
        self.manifest["cases"].append({**self.case, "case_id": "B"})
        with patch.dict(module.ADAPTERS, {"GX3-FX5": lambda *_: self.observation()}), patch(
                "gx_re_lab.corpus_census._retained_bytes", wraps=module._retained_bytes) as retained:
            result = module.corpus_census(self.manifest, self.root)
        self.assertEqual(4, retained.call_count)
        self.assertEqual((2, 1), (result["case_count"], result["unique_inputs"]))
        self.assertEqual(["A", "B"], result["duplicate_inputs"][0]["case_ids"])
        self.assertEqual([], result["reused_container_keys"])
        self.assertEqual("NOT_MEASURED", result["semantic_coverage"])

    def test_reused_key_different_content_is_not_a_global_identity(self):
        self.manifest["cases"].append({**self.case, "case_id": "B"})
        calls = iter([self.observation("a" * 64), self.observation("b" * 64)])
        result = self.run_census(lambda *_: next(calls))
        variants = result["reused_container_keys"]
        self.assertEqual(1, len(variants))
        self.assertEqual([{"content_sha256": "a" * 64, "case_ids": ["A"]},
                          {"content_sha256": "b" * 64, "case_ids": ["B"]}], variants[0]["variants"])
        self.assertNotIn("same-internal-key", json.dumps(result))

    def test_same_key_in_separate_adapters_stays_separate(self):
        self.manifest["cases"].append({**self.case, "case_id": "B", "path": "b.gxw", "adapter": "GXW-Q"})
        gxw = {"topology": {"pou": {"observed_count": 1}, "record": {"reader_row_count": 2}},
               "container": {"hdb_substream_count": 1, "hdb_substreams": [
                   {"stream": "same-internal-key", "sha256": "b" * 64}]}}
        with patch.dict(module.ADAPTERS, {"GX3-FX5": lambda *_: self.observation(), "GXW-Q": lambda *_: gxw}):
            result = module.corpus_census(self.manifest, self.root)
        self.assertEqual([], result["reused_container_keys"])
        self.assertEqual({"GX3-FX5": 1, "GXW-Q": 1}, result["adapters"])

    def test_bad_pin_remains_a_blocked_case_and_other_case_runs(self):
        self.manifest["cases"].append({**self.case, "case_id": "B"})
        self.case["sha256"] = "0" * 64
        result = self.run_census()
        self.assertEqual("CORPUS_WITH_BLOCKS", result["decision"])
        self.assertEqual({"BLOCKED": 1, "STRUCTURE_OBSERVED": 1}, result["states"])
        self.assertEqual("CORPUS_SOURCE_PIN_MISMATCH", result["cases"][0]["reason"])
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_source_change_during_adapter_is_blocked(self):
        def mutate(*_):
            (self.root / "a.gx3").write_bytes(b"changed")
            return self.observation()
        result = self.run_census(mutate)
        self.assertEqual("CORPUS_SOURCE_CHANGED", result["cases"][0]["reason"])

    def test_snapshot_identity_exception_keeps_first_case_and_continues(self):
        self.manifest["cases"].append({**self.case, "case_id": "B"})
        read = module._retained_bytes
        calls = 0
        def unstable_read(*args):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("input identity changed: private name")
            return read(*args)
        with patch.object(module, "_retained_bytes", side_effect=unstable_read):
            result = self.run_census()
        self.assertEqual(["BLOCKED", "STRUCTURE_OBSERVED"], [r["decision"] for r in result["cases"]])
        self.assertNotIn("private name", json.dumps(result))

    def test_adapter_gets_retained_copy_and_failures_do_not_leak_names(self):
        def adapter(path, pin):
            self.assertNotEqual(self.root / "a.gx3", path)
            self.assertEqual(self.body, path.read_bytes())
            self.assertEqual(self.case["sha256"], pin)
            raise ValueError("private name: " + str(self.root))
        result = self.run_census(adapter)
        self.assertEqual("CORPUS_CENSUS_FAILED", result["cases"][0]["reason"])
        self.assertNotIn("private name", json.dumps(result))

    def test_large_fx5_input_is_retained_without_relaxing_archive_budget(self):
        body = b"x" * (16 * 1024 * 1024 + 1)
        source = self.root / "large.gx3"
        source.write_bytes(body)
        self.manifest["cases"] = [{**self.case, "path": source.name, "byte_count": len(body),
                                   "sha256": hashlib.sha256(body).hexdigest()}]
        result = self.run_census()
        self.assertEqual("CORPUS_OBSERVED", result["decision"])
        self.assertEqual(len(body), result["cases"][0]["byte_count"])
        with patch.object(module.fx5, "SafeGx3Archive", side_effect=ValueError("stop before inflate")) as archive:
            with self.assertRaisesRegex(ValueError, "stop before inflate"):
                module.fx5.census(source, hashlib.sha256(body).hexdigest())
        budget = archive.call_args.args[1]
        self.assertEqual((32 * 1024 * 1024, 2000, 16 * 1024 * 1024, 64 * 1024 * 1024),
                         (budget.max_input_bytes, budget.max_entries, budget.max_entry_bytes, budget.max_total_bytes))

    def test_path_and_identifier_schema_rejects_before_reads(self):
        for path in ("../a.gx3", "x/../a.gx3", "/a.gx3", "C:/a.gx3", "x\\a.gx3", "a.gxw", "x//a.gx3", "a.gx3:stream"):
            value = deepcopy(self.manifest)
            value["cases"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(LabError):
                module.validate_manifest(value)
        value = deepcopy(self.manifest)
        value["cases"].append(deepcopy(value["cases"][0]))
        with self.assertRaisesRegex(LabError, "CORPUS_CASE_ID"):
            module.validate_manifest(value)

    def test_limits_and_boolean_numbers_fail_closed(self):
        for field, invalid in (("byte_count", True), ("byte_count", module.MAX_INPUT_BYTES + 1),
                               ("sha256", "A" * 64), ("adapter", "AUTO")):
            value = deepcopy(self.manifest)
            value["cases"][0][field] = invalid
            with self.subTest(field=field), self.assertRaises(LabError):
                module.validate_manifest(value)
        for changes in ({"version": True}, {"cases": []}, {"unexpected": 1}):
            with self.subTest(changes=changes), self.assertRaises(LabError):
                module.validate_manifest({**self.manifest, **changes})
        with patch.object(module, "MAX_TOTAL_BYTES", len(self.body) - 1), self.assertRaisesRegex(LabError, "CORPUS_TOTAL_CAP"):
            module.validate_manifest(self.manifest)

    def test_cli_refuses_to_overwrite_and_records_pin(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(self.manifest), encoding="utf-8")
        pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
        target = self.root / "new.json"
        args = ["--manifest", str(manifest), "--manifest-sha256", pin,
                "--source-root", str(self.root), "--output", str(target)]
        with patch.dict(module.ADAPTERS, {"GX3-FX5": lambda *_: self.observation()}):
            self.assertEqual(0, module.main(args))
            original = target.read_bytes()
            self.assertEqual(1, module.main(args))
        self.assertEqual(original, target.read_bytes())


if __name__ == "__main__":
    unittest.main()
