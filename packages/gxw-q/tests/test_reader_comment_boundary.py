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
