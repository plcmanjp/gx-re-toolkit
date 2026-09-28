"""Synthetic GXW comment and instruction boundary regressions."""

from __future__ import annotations

import struct
import unittest

import gxw_ladder_reader as reader


def _range(code: int, address: int, count: int) -> bytes:
    return bytes((code, 0)) + struct.pack("<H", address) + b"\0\0" + struct.pack("<I", count)


def _module_range(module: int, address: int, count: int) -> bytes:
    return b"\xab\xf8" + struct.pack("<HHI", address, module, count)


def _comment(value: str, padding: bytes = b"\0" * 4) -> bytes:
    return struct.pack("<I", len(value) + 1) + value.encode("utf-16le") + b"\0\0" + padding


class CommentBoundaryTests(unittest.TestCase):
    @staticmethod
    def _split_stream(*, second_count: int = 30, duplicate: bool = False,
                      gap: bytes | None = None) -> bytes:
        second_start = 0 if duplicate else 30
        directory = _range(0x90, 0, 30) + _range(0x90, second_start, 30)
        first = b"".join(_comment(f"first {i}") for i in range(30))
        second = b"".join(_comment(f"second {i}") for i in range(second_count))
        if gap is None:
            gap = _comment("MODULE1") + _comment("MODULE2")
        return directory + first + gap + second

    def test_split_chains_preserve_source_order_and_report_unaddressed_labels(self) -> None:
        stream = self._split_stream()
        directory = reader.unified_directory(stream)
        verified = reader.verified_split_comment_chains(stream, directory)
        self.assertIsNotNone(verified)
        comments, excluded = verified
        self.assertEqual(60, len(comments))
        self.assertEqual(2, excluded)
        self.assertEqual("first 0", comments[0])
        self.assertEqual("second 0", comments[30])
        pairs, warning = reader.device_comment_pairs({"synthetic": stream})
        self.assertEqual(("UnaddressedModuleLabels", 2), warning)
        self.assertEqual(60, len(pairs))
        self.assertEqual(("M30", "second 0"), pairs[30])

    def test_split_chains_reject_missing_duplicate_or_ambiguous_content(self) -> None:
        cases = (
            self._split_stream(second_count=29),
            self._split_stream(duplicate=True),
            self._split_stream(gap=_comment("MODULE1") + _comment("ambiguous text")),
        )
        for stream in cases:
            with self.subTest(stream_length=len(stream)):
                self.assertIsNone(reader.verified_split_comment_chains(
                    stream, reader.unified_directory(stream)))
                _pairs, warning = reader.device_comment_pairs({"synthetic": stream})
                self.assertNotEqual(("UnaddressedModuleLabels", 2), warning)

    def test_split_chain_cannot_take_first_pass_count_shortcut(self) -> None:
        stream = (
            _range(0x90, 0, 30) + _module_range(2, 100, 30)
            + b"".join(_comment(f"first {i}") for i in range(30))
            + _comment("MODULE1")
            + b"".join(_comment(f"second {i}") for i in range(30))
        )
        self.assertEqual(30, len(reader.comment_directory(stream)))
        pairs, warning = reader.device_comment_pairs({"synthetic": stream})
        self.assertEqual(60, len(pairs))
        self.assertEqual(("UnaddressedModuleLabels", 1), warning)
        self.assertEqual(("U2\\G100", "second 0"), pairs[30])

    def test_split_chains_reject_unreported_outer_labels(self) -> None:
        stream = self._split_stream()
        directory_size = 2 * len(_range(0x90, 0, 30))
        cases = (
            stream[:directory_size] + _comment("MODULE0") + stream[directory_size:],
            stream + _comment("MODULE3"),
            stream[:directory_size] + _comment("MODULE0") + stream[directory_size:] + _comment("MODULE3"),
        )
        for candidate in cases:
            with self.subTest(stream_length=len(candidate)):
                directory = reader.unified_directory(candidate)
                self.assertIsNone(reader.verified_split_comment_chains(candidate, directory))
                _pairs, warning = reader.device_comment_pairs({"synthetic": candidate})
                self.assertNotEqual(("UnaddressedModuleLabels", 2), warning)

    def test_comment_text_cannot_be_reinterpreted_as_directory(self) -> None:
        directory = (
            b"\0" * 10
            + _range(0x9C, 1, 1)
            + _range(0x91, 400, 1)
            + _range(0xAF, 17, 1)
            + _module_range(1, 99, 1)
        )
        stream = (
            directory
            + _comment("alpha\u00c5a", b"\0\x1b\0\0")
            + _comment("system one")
            + _comment("relay one")
            + _comment("buffer one")
        )
        self.assertEqual(len(directory), reader._longest_comment_run(stream)[0])
        self.assertEqual(["X1", "SM400", "R17"], reader.comment_directory(stream))
        self.assertEqual(["X1", "SM400", "R17", "U1\\G99"], reader.unified_directory(stream))
        self.assertEqual(
            ([
                ("X1", "alpha\u00c5a"),
                ("SM400", "system one"),
                ("R17", "relay one"),
                ("U1\\G99", "buffer one"),
            ], None),
            reader.device_comment_pairs({"synthetic": stream}),
        )

    def test_oversized_directory_fails_before_address_expansion(self) -> None:
        stream = _range(0x90, 0, 60_000) + _range(0x90, 1, 60_000)
        with self.assertRaisesRegex(ValueError, "entry budget"):
            reader.comment_directory(stream)
        with self.assertRaisesRegex(ValueError, "entry budget"):
            reader.unified_directory(stream)


class InstructionOperandTests(unittest.TestCase):
    def test_shift_pulse_arity_and_double_modifier_edge(self) -> None:
        program = bytes.fromhex(
            "03000304900104"  # LD M1
            "06510404020604a8110404e80a04"  # DSFRP D17 K10
            "0408040404f8010404f2000404ab6304"  # ORP U1\\G99.0
            "03190304"  # ANB, END
        )
        self.assertEqual(
            [("LD", "M1"), ("DSFRP", "D17 K10"), ("ORP", "U1\\G99.0"),
             ("ANB", ""), ("END", "")],
            reader.decode_program(program),
        )

    def test_hex_constant_preserves_unambiguous_leading_zero(self) -> None:
        self.assertEqual(("H0FF", 4), reader._read_operand(bytes.fromhex("04eaff04"), 0))
        self.assertEqual(("H0ABCD", 5), reader._read_operand(bytes.fromhex("05eacd ab05"), 0))


if __name__ == "__main__":
    unittest.main()
