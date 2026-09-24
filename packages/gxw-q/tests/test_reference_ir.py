"""Synthetic reference-IR checks for grouped bit-device operands."""

from __future__ import annotations

import importlib
import unittest


REFERENCE = importlib.import_module("gxw_reference_ir")


class GroupedDeviceReferenceTests(unittest.TestCase):
    def test_grouped_x_y_are_devices_and_numeric_literals_remain_constants(self) -> None:
        for raw, family, address, digit_width in (
            ("K1X110", "X", 0x110, 1),
            ("K2Y200", "Y", 0x200, 2),
            ("K8X1F0", "X", 0x1F0, 8),
        ):
            with self.subTest(raw=raw):
                operand = REFERENCE.parse_operand(raw, 0)
                self.assertEqual(("device", "decoded"), (operand["kind"], operand["status"]))
                self.assertEqual((family, address, digit_width),
                                 (operand["device"]["family"], operand["device"]["address"],
                                  operand["device"]["digit_width"]))
        for raw, notation, value in (("K10", "K", 10), ("H10", "H", 16), ("E1", "E", 1)):
            with self.subTest(raw=raw):
                operand = REFERENCE.parse_operand(raw, 0)
                self.assertEqual(("constant", "decoded", notation, value),
                                 (operand["kind"], operand["status"],
                                  operand["constant"]["notation"], operand["constant"]["value"]))
        self.assertEqual("unknown", REFERENCE.parse_operand("K9X110", 0)["status"])

    def test_mov_grouped_bit_coverage_expands_entire_width(self) -> None:
        rows = [("LD", "M0", ""), ("MOV", "K1X110 D100", ""),
                ("MOV", "D100 K2Y200", ""), ("END", "", "")]
        result = REFERENCE.project_rows(
            [{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
              "rows": rows}], input_sha256="a" * 64,
        )
        self.assertEqual("COMPLETE", result["analysis"]["state"])
        self.assertEqual("NOT_GRANTED", result["analysis"]["production_adoption"])
        for occurrence, index, family, first, count in (
            (result["occurrences"][1], 0, "X", 0x110, 4),
            (result["occurrences"][2], 1, "Y", 0x200, 8),
        ):
            operand = occurrence["operands"][index]
            self.assertEqual("DIGIT_BIT_WIDTH", operand["coverage"]["reason"])
            self.assertEqual([first + offset for offset in range(count)],
                             [row["address"] for row in operand["coverage"]["addresses"]])
            self.assertEqual({family}, {row["family"] for row in operand["coverage"]["addresses"]})

    def test_indexed_and_block_grouped_spans_are_not_guessed(self) -> None:
        rows = [("MOV", "K2Y200Z1 D100", ""),
                ("BMOV", "K1X110 D100 K2", ""),
                ("MOV", "@K1X110 D101", "")]
        result = REFERENCE.project_rows(
            [{"name": "MAIN", "source_store": "synthetic", "source_digest": "e" * 64,
              "rows": rows}], input_sha256="b" * 64,
        )
        indexed = result["occurrences"][0]["operands"][0]
        block = result["occurrences"][1]["operands"][0]
        self.assertEqual(("DYNAMIC", None, "INDEX_OR_INDIRECT_ADDRESS"),
                         (indexed["coverage"]["state"], indexed["coverage"]["addresses"],
                          indexed["coverage"]["reason"]))
        self.assertEqual(("UNKNOWN", None, "DIGIT_BLOCK_SPAN_UNVERIFIED"),
                         (block["coverage"]["state"], block["coverage"]["addresses"],
                          block["coverage"]["reason"]))
        indirect = result["occurrences"][2]["operands"][0]
        self.assertEqual(("DYNAMIC", None, "INDEX_OR_INDIRECT_ADDRESS"),
                         (indirect["coverage"]["state"], indirect["coverage"]["addresses"],
                          indirect["coverage"]["reason"]))


if __name__ == "__main__":
    unittest.main()
