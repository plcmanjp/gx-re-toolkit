"""Synthetic reference-IR checks for grouped bit-device operands."""

from __future__ import annotations

import importlib
import unittest


REFERENCE = importlib.import_module("gxw_reference_ir")


class GroupedDeviceReferenceTests(unittest.TestCase):
    def test_reader_control_tokens_and_indexed_k_constant_are_classified_without_target_claim(self) -> None:
        for raw in ("N0", "N12", "P0", "P400"):
            with self.subTest(raw=raw):
                operand = REFERENCE.parse_operand(raw, 0)
                self.assertEqual(("control", "decoded", None, None),
                                 (operand["kind"], operand["status"], operand["device"],
                                  operand["constant"]))
                self.assertEqual(raw, operand["raw_token"])
        indexed = REFERENCE.parse_operand("K0Z16", 0)
        self.assertEqual(("constant", "decoded", "K", 0),
                         (indexed["kind"], indexed["status"],
                          indexed["constant"]["notation"], indexed["constant"]["value"]))
        self.assertEqual({"kind": "Z", "number": 16, "access": "read"},
                         indexed["constant"]["index"])

        rows = [("MC", "N0 M0", ""), ("MCR", "N0", ""),
                ("CALL", "P400", ""), ("XCALL", "P1", ""),
                ("MOV", "K0Z16 D10", "")]
        result = REFERENCE.project_rows(
            [{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
              "rows": rows}], input_sha256="a" * 64,
        )
        self.assertEqual((REFERENCE.SCHEMA_NAME, REFERENCE.SCHEMA_VERSION),
                         (result["schema_name"], result["schema_version"]))
        self.assertEqual("COMPLETE", result["analysis"]["state"])
        for occurrence in result["occurrences"][:4]:
            control = occurrence["operands"][0]
            self.assertEqual(("decoded", "read", "OBSERVED_CONTROL_READ_FORM"),
                             (control["status"], control["access"], control["access_basis"]))
        indexed_coverage = result["occurrences"][4]["operands"][0]["coverage"]
        self.assertEqual(("DYNAMIC", None, "INDEXED_CONSTANT_ADDRESS"),
                         (indexed_coverage["state"], indexed_coverage["addresses"],
                          indexed_coverage["reason"]))

    def test_control_and_indexed_constant_negative_grammar_stays_unknown(self) -> None:
        for raw in ("N", "P", "N-1", "P+1", "N1Z2", "P1.0", "KZ16", "K0Z", "K0ZZ16",
                    "K0Z-1", "H0Z16", "K0Z16.0"):
            with self.subTest(raw=raw):
                self.assertEqual("unknown", REFERENCE.parse_operand(raw, 0)["status"])

    def test_indexed_k_count_does_not_create_static_bmov_or_fmov_spans(self) -> None:
        rows = [("BMOV", "D0 D100 K3Z1", ""), ("FMOV", "K5 D200 K3Z1", "")]
        result = REFERENCE.project_rows(
            [{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
              "rows": rows}], input_sha256="a" * 64,
        )
        self.assertEqual("COMPLETE", result["analysis"]["state"])
        for occurrence, positions in zip(result["occurrences"], ((0, 1), (1,))):
            for position in positions:
                with self.subTest(opcode=occurrence["record"]["opcode"], position=position):
                    coverage = occurrence["operands"][position]["coverage"]
                    self.assertEqual(("DYNAMIC", None, "COUNT_NOT_STATIC_K"),
                                     (coverage["state"], coverage["addresses"], coverage["reason"]))
            count = occurrence["operands"][2]["coverage"]
            self.assertEqual(("DYNAMIC", None, "INDEXED_CONSTANT_ADDRESS"),
                             (count["state"], count["addresses"], count["reason"]))

    def test_control_context_and_indexed_k_write_are_not_claimed(self) -> None:
        for opcode, text, index in (("OUT", "P400", 0), ("MOV", "N0 D10", 0),
                                    ("MOV", "D0 K0Z16", 1)):
            with self.subTest(opcode=opcode, text=text):
                result = REFERENCE.project_rows(
                    [{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
                      "rows": [(opcode, text, "")]}], input_sha256="a" * 64,
                )
                operand = result["occurrences"][0]["operands"][index]
                self.assertEqual("decoded", operand["status"])
                self.assertEqual("unknown", operand["access"])
                self.assertEqual("PARTIAL", result["analysis"]["state"])

    def test_oversize_indexed_k_numbers_fail_closed(self) -> None:
        huge = "9" * 5000
        for raw in (f"K{huge}Z16", f"K0Z{huge}"):
            with self.subTest(component="value" if raw.startswith("K9") else "index"):
                operand = REFERENCE.parse_operand(raw, 0)
                self.assertEqual(("unknown", "unknown"), (operand["kind"], operand["status"]))

    def test_quoted_literal_with_spaces_keeps_raw_operand_and_position(self) -> None:
        text = '"ALPHA BETA" D10'
        self.assertEqual(['"ALPHA BETA"', "D10"], REFERENCE.split_operands(text))
        result = REFERENCE.project_rows(
            [{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
              "rows": [("MOV", text, "")]}], input_sha256="a" * 64,
        )
        self.assertEqual("COMPLETE", result["analysis"]["state"])
        operands = result["occurrences"][0]["operands"]
        self.assertEqual([('"ALPHA BETA"', "literal", "decoded", 0),
                          ("D10", "device", "decoded", 1)],
                         [(item["raw_token"], item["kind"], item["status"], item["position"])
                          for item in operands])

    def test_malformed_quotes_preserve_text_and_leave_projection_partial(self) -> None:
        for text, raw_tokens in (
            ('"ALPHA BETA D10', ['"ALPHA BETA D10']),
            ('"ALPHA"BETA D10', ['"ALPHA"BETA', "D10"]),
            ('"ALPHA""BETA" D10', ['"ALPHA""BETA"', "D10"]),
            ('D10" M0', ['D10" M0']),
        ):
            with self.subTest(text=text):
                self.assertEqual(raw_tokens, REFERENCE.split_operands(text))
                result = REFERENCE.project_rows(
                    [{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
                      "rows": [("MOV", text, "")]}], input_sha256="a" * 64,
                )
                self.assertEqual("PARTIAL", result["analysis"]["state"])
                self.assertEqual("unknown", result["occurrences"][0]["operands"][0]["status"])

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
