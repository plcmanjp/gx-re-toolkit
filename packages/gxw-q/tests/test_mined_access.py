"""Synthetic bounded manual-derived access/range regressions."""
import unittest
from unittest.mock import patch
import gxw_reference_ir as ref


def project(opcode, text):
    return ref.project_rows([{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
                              "rows": [(opcode, text, "raw comment")]}], input_sha256="a" * 64)


def operands(opcode, text):
    return project(opcode, text)["occurrences"][0]["operands"]


class MinedAccessTests(unittest.TestCase):
    def test_fixed_roles_and_word_widths(self):
        for opcode, text, roles, widths in (
            ("SUM", "D0 D100", ["read", "write"], [1, 1]),
            ("SEG", "D0 D100", ["read", "write"], [1, 1]),
            ("DBCD", "D0 D100", ["read", "write"], [2, 2]),
            ("DXOR", "D0 D100", ["read", "both"], [2, 2]),
            ("DXOR", "D0 D10 D100", ["read", "read", "write"], [2, 2, 2]),
            ("SER", "D0 D10 D100 K5", ["read", "read", "write", "read"], [1, 5, 2, None]),
            ("UNI", "D0 D100 K4", ["read", "write", "read"], [4, 1, None]),
            ("WSUM", "D0 D100 K5", ["read", "write", "read"], [5, 2, None]),
        ):
            with self.subTest(opcode=opcode, text=text):
                result = operands(opcode, text)
                self.assertEqual([r["access"] for r in result], roles)
                self.assertEqual([r["coverage"]["word_width"] for r in result], widths)
                self.assertEqual([r["raw_token"] for r in result], text.split())

    def test_ser_keyword_and_array_are_not_reversed(self):
        values = operands("SER", "D1 D20 D100 K3")
        self.assertEqual([v["address"] for v in values[0]["coverage"]["addresses"]], [1])
        self.assertEqual([v["address"] for v in values[1]["coverage"]["addresses"]], [20, 21, 22])

    def test_wrong_arity_never_uses_legacy_fallback(self):
        for opcode in ("SUM", "SEG", "SER", "UNI", "WSUM", "DBCD", "DXOR", "DZCP", "$+", "LEN", "SORT"):
            with self.subTest(opcode=opcode):
                values = operands(opcode, "D0")
                self.assertTrue(all(v["access"] == "unknown" for v in values))
                self.assertTrue(all(v["coverage"]["state"] == "UNKNOWN" for v in values))
                self.assertEqual(project(opcode, "D0")["analysis"]["state"], "PARTIAL")
                self.assertEqual(project(opcode, "")["analysis"]["state"], "PARTIAL")

    def test_count_dynamic_invalid_and_limit(self):
        for count in ("D99", "H4", "K4Z0", "K+4"):
            with self.subTest(count=count):
                value = operands("WSUM", "D0 D100 " + count)[0]
                self.assertEqual(value["coverage"]["state"], "DYNAMIC")
                self.assertIsNone(value["coverage"]["addresses"])
        for opcode, text, index in (("SER", "D0 D10 D100 K0", 1), ("WSUM", "D0 D100 K-1", 0),
                                    ("UNI", "D0 D100 K5", 0), ("UNI", "D0 D100 K0", 0)):
            self.assertEqual(operands(opcode, text)[index]["coverage"]["state"], "UNKNOWN")
        limit = ref.MAX_COVERED_ADDRESSES
        value = operands("WSUM", f"D0 D100 K{limit + 1}")[0]
        self.assertEqual(value["coverage"]["state"], "LIMIT_REACHED")
        self.assertIsNone(value["coverage"]["addresses"])
        self.assertEqual(len(operands("WSUM", f"D0 D100 K{limit}")[0]["coverage"]["addresses"]), limit)
        with patch.object(ref, "MAX_TOTAL_COVERED_ADDRESSES", 3):
            with self.assertRaisesRegex(ref.ReferenceIrError, "COVERED_ADDRESS_TOTAL_LIMIT"):
                project("DBCD", "D0 D100")

    def test_word_form_guards_and_existing_sum_digit_group(self):
        for source in ("M0", "D0.1", "K4M0"):
            for opcode, text in (("DBCD", source + " D100"), ("WSUM", source + " D100 K2")):
                with self.subTest(opcode=opcode, source=source):
                    self.assertEqual(operands(opcode, text)[0]["coverage"]["state"], "UNKNOWN")
        self.assertEqual(len(operands("SUM", "K4M0 D100")[0]["coverage"]["addresses"]), 16)
        self.assertEqual(operands("DBCD", "D0Z1 D100")[0]["coverage"]["state"], "DYNAMIC")

    def test_string_ranges_and_analysis_never_fake_one_word(self):
        for opcode, text, roles, positions in (
            ("$+", "D0 D100", ["read", "both"], (0, 1)),
            ("$+", "D0 D10 D100", ["read", "read", "write"], (0, 1, 2)),
            ("LEN", "D0 D100", ["read", "write"], (0,)),
        ):
            values = operands(opcode, text)
            self.assertEqual([v["access"] for v in values], roles)
            self.assertEqual(project(opcode, text)["analysis"]["state"], "PARTIAL")
            for position in positions:
                self.assertEqual(values[position]["coverage"]["state"], "DYNAMIC")
                self.assertIsNone(values[position]["coverage"]["word_width"])
                self.assertIsNone(values[position]["coverage"]["addresses"])

    def test_bit_results_and_reserved_sort_workspace(self):
        values = operands("DZCP", "D0 D10 D20 M100")
        self.assertEqual([v["access"] for v in values], ["read", "read", "read", "write"])
        self.assertEqual([v["address"] for v in values[3]["coverage"]["addresses"]], [100, 101, 102])
        self.assertIsNone(values[3]["coverage"]["word_width"])
        for dest in ("D100", "D100Z0", "D100.0", "K4M100", "K0"):
            self.assertEqual(operands("DZCP", "D0 D10 D20 " + dest)[3]["coverage"]["state"], "UNKNOWN")
        indexed = operands("DZCP", "D0 D10 D20 M100Z0")[3]["coverage"]
        self.assertEqual(indexed["state"], "DYNAMIC")
        self.assertIsNone(indexed["word_width"])
        values = operands("SORT", "D0 K3 D10 M20 D100")
        self.assertEqual([v["access"] for v in values], ["both", "read", "read", "write", "unknown"])
        self.assertEqual(values[4]["access_basis"], "RESERVED_WORKSPACE_ACCESS_UNVERIFIED")
        self.assertEqual(len(values[4]["coverage"]["addresses"]), 2)
        self.assertEqual([v["address"] for v in values[3]["coverage"]["addresses"]], [20])

    def test_no_automatic_p_variant_and_nonstatic_device_analysis_is_partial(self):
        self.assertNotEqual(operands("SUMP", "D0 D100")[0]["access_basis"], "MANUAL_OPERAND_ROLE")
        self.assertEqual(project("BMOV", "D0 D100 K3Z1")["analysis"]["state"], "PARTIAL")

    def test_mined_write_nondevice_is_unknown_but_read_constant_is_preserved(self):
        for opcode, text, target in (("SUM", "D0 K0", 1), ("DXOR", "D0 K0", 1),
                                     ("$+", 'D0 "TARGET"', 1), ("DZCP", "D0 D10 D20 K0", 3)):
            with self.subTest(opcode=opcode):
                result = project(opcode, text)
                value = result["occurrences"][0]["operands"][target]
                self.assertEqual(value["access"], "unknown")
                self.assertEqual(value["access_basis"], "MINED_WRITE_TARGET_UNVERIFIED")
                self.assertEqual(value["coverage"]["state"], "UNKNOWN")
                self.assertEqual(value["coverage"]["reason"], "MINED_WRITE_TARGET_UNVERIFIED")
                self.assertEqual(result["analysis"]["state"], "PARTIAL")
        result = project("SUM", "K0 D0")
        self.assertEqual(result["analysis"]["state"], "COMPLETE")
        source = result["occurrences"][0]["operands"][0]
        self.assertEqual(source["access"], "read")
        self.assertEqual(source["coverage"]["state"], "NOT_APPLICABLE")

    def test_bit_result_family_requires_observed_m_and_empty_arity_has_location(self):
        for family in ("T", "ST", "C", "X", "Y", "B", "SM"):
            value = operands("DZCP", "D0 D10 D20 " + family + "0")[-1]
            self.assertEqual(value["coverage"]["state"], "UNKNOWN")
            self.assertEqual(value["coverage"]["reason"], "BIT_RESULT_FORM_UNVERIFIED")
        result = project("SUM", "")
        self.assertEqual(result["analysis"]["state"], "PARTIAL")
        finding = result["diagnostics"][0]
        self.assertEqual(finding["reason"], "MINED_FORM_ARITY_UNVERIFIED")
        self.assertEqual((finding["pou"], finding["source_store"], finding["row"]), ("MAIN", "synthetic", 0))
        self.assertEqual(finding["source_locator"], "_hdb/synthetic:row:0")


if __name__ == "__main__":
    unittest.main()
