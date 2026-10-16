"""Synthetic metadata only; no source archive, native app or PLC authority."""
from copy import deepcopy
import unittest

from gx_re_lab.reading_scope import build_reading_scope, ReadingScopeError


def fixture(profile="mitsubishi.gx3.fx5u.ladder"):
    return {"schema_name": "plcman.gx3.neutral-ir", "schema_version": "1.0.0",
            "producer": {"package": "synthetic", "version": "1.0", "source_commit": "a" * 40}, "input": {"display_id": "synthetic", "sha256": "a" * 64,
                                      "byte_count": 10, "read_only_unchanged": True},
            "profile": {"profile_id": profile, "contract_version": "1.0.0", "family": "synthetic",
                        "cpu_ui_selection": "synthetic", "language": "Ladder",
                        "detector_status": "SUPPORTED", "evidence": []},
            "project": {"project_id": "synthetic", "provenance": {"source_entry": "CPU.PRM", "source_store": "synthetic",
                        "source_locator": "synthetic", "source_digest": "b" * 64, "relation_evidence": []}},
            "pous": [], "comments": [], "labels": [], "findings": [],
            "coverage": {key: {"total": 1, "decoded": 1, "partial": 0, "unknown": 0}
                         for key in ("project", "pou", "record", "comment", "label")}}


def entry(name):
    return {"name": name, "sha256": "b" * 64, "byte_count": 0}


class ReadingScopeTests(unittest.TestCase):
    def test_full_ir_and_all_categories_never_imply_project_complete(self):
        for profile in ("mitsubishi.gx3.fx5u.ladder", "mitsubishi.gx3.r04cpu.ladder"):
            ir = fixture(profile)
            entries = [entry(name) for name in ("CPU.PRM", "UNIT.PRM", "Settings/a.w3pa",
                       "Resource/Program.qpg", "Resource/PouLinkOrder.info", "ConvertData/1/PouPCode.pcode", "_Project.txc")]
            before = deepcopy((ir, entries))
            result = build_reading_scope(ir, entries)
            self.assertFalse(result["project_reading_complete"])
            self.assertEqual(result["decision"], "PARTIAL")
            self.assertEqual(result["diagnostics"], [])
            self.assertEqual(result["ir_coverage"], ir["coverage"])
            self.assertIsNone(result["source_coverage"]["denominator"])
            self.assertEqual(result, build_reading_scope(ir, entries[::-1]))
            self.assertEqual((ir, entries), before)
            result["ir_coverage"]["project"]["decoded"] = 0
            self.assertEqual(ir["coverage"]["project"]["decoded"], 1)
            order = next(row for row in result["entries"] if row["category"] == "pou_link_order")
            self.assertIn("not CPU registration", order["reason"])

    def test_unknown_and_missing_are_explicit(self):
        result = build_reading_scope(fixture(), [entry("Mystery.bin")])
        self.assertEqual(result["entries"][0]["category"], "unknown")
        self.assertEqual(sum(d["code"] == "MISSING_REQUIRED_CATEGORY" for d in result["diagnostics"]), 7)
        self.assertTrue(any(d["code"] == "UNKNOWN_ENTRY_CATEGORY" for d in result["diagnostics"]))

    def test_finding_locations_and_reasons_are_retained(self):
        ir = fixture()
        ir["findings"] = [{"finding_code": "MINING_REQUIRED", "scope": "project",
                           "object_kind": "parameter", "locator": "CPU.PRM",
                           "digest": "b" * 64, "reason": "synthetic undecoded setting"}]
        result = build_reading_scope(ir, [entry("CPU.PRM")])
        self.assertEqual(result["ir_findings"], ir["findings"])
        self.assertEqual(result["entries"][0]["ir_locations"], ["/findings/0", "/project/provenance"])

    def test_rejects_gxw_unknown_profile_and_invalid_schema(self):
        for field, value in (("schema_name", "plcman.gxw.reference-ir"),
                             ("coverage", {}), ("input", {})):
            ir = fixture(); ir[field] = value
            with self.subTest(field=field), self.assertRaises(ReadingScopeError):
                build_reading_scope(ir, [])
        with self.assertRaisesRegex(ReadingScopeError, "UNSUPPORTED_PROFILE"):
            build_reading_scope(fixture("future"), [])

    def test_rejects_bad_metadata_duplicates_and_inconsistent_counts(self):
        for invalid in ({**entry("x"), "byte_count": True}, {**entry("x"), "sha256": "B" * 64},
                        entry("../x"), entry("/x"), entry("x\\y"), entry("C:/x"), entry("x\x00")):
            with self.subTest(invalid=invalid), self.assertRaises(ReadingScopeError):
                build_reading_scope(fixture(), [invalid])
        with self.assertRaisesRegex(ReadingScopeError, "DUPLICATE_ENTRY"):
            build_reading_scope(fixture(), [entry("CPU.PRM"), entry("cpu.prm")])
        ir = fixture(); ir["coverage"]["project"]["total"] = 2
        with self.assertRaisesRegex(ReadingScopeError, "COVERAGE_SCHEMA"):
            build_reading_scope(ir, [])

    def test_cycles_and_deep_payloads_fail_explicitly(self):
        ir = fixture(); ir["project"]["cycle"] = ir["project"]
        with self.assertRaisesRegex(ReadingScopeError, "INPUT_LIMIT"):
            build_reading_scope(ir, [])

    def test_provenance_requires_exact_entry_without_assuming_row_digest_scope(self):
        ir = fixture()
        provenance = {"source_entry": "x.pcode", "source_store": "synthetic",
                      "source_locator": "row=1", "source_digest": "b" * 64, "relation_evidence": []}
        record = {"record_id": "1", "sequence": 0, "kind": "instruction", "step": 0,
                  "opcode": "END", "operands": [], "text": None, "status": "decoded",
                  "continues_record_id": None, "provenance": provenance}
        ir["pous"] = [{"pou_id": "1", "name": "Main", "language": "Ladder", "execution_order": 0,
                       "program_kind": "PRG", "relations": ["x.pcode"], "records": [record], "findings": []}]
        result = build_reading_scope(ir, [entry("x.pcode"), entry("CPU.PRM")])
        self.assertIn("/pous/0/records/0/provenance", result["entries"][1]["ir_locations"])
        self.assertEqual(result["entries"][1]["semantic_status"], "NOT_ESTABLISHED")
        provenance["source_digest"] = "c" * 64
        result = build_reading_scope(ir, [entry("x.pcode"), entry("CPU.PRM")])
        self.assertFalse(any(d["code"] == "UNBOUND_IR_PROVENANCE" for d in result["diagnostics"]))
        provenance["source_entry"] = "missing.pcode"
        result = build_reading_scope(ir, [entry("x.pcode"), entry("CPU.PRM")])
        self.assertEqual(result["diagnostics"][-1]["code"], "UNBOUND_IR_PROVENANCE")

    def test_full_schema_rejects_invalid_identity_producer_and_record_types(self):
        for change in (lambda x: x.update(producer={}), lambda x: x.update(project={}),
                       lambda x: x["input"].update(read_only_unchanged=False),
                       lambda x: x["profile"].update(detector_status=[])):
            ir = fixture(); change(ir)
            with self.assertRaisesRegex(ReadingScopeError, "IR_SCHEMA"):
                build_reading_scope(ir, [])

    def test_project_and_profile_provenance_are_not_silently_unbound(self):
        ir = fixture()
        ir["profile"]["evidence"] = [deepcopy(ir["project"]["provenance"])]
        result = build_reading_scope(ir, [])
        self.assertEqual({"/project/provenance", "/profile/evidence/0"},
                         {d["ir_location"] for d in result["diagnostics"] if d["code"] == "UNBOUND_IR_PROVENANCE"})


if __name__ == "__main__":
    unittest.main()
