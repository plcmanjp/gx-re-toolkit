"""Synthetic, opt-in ASCII Note subtype regressions."""

from __future__ import annotations

import unittest
from unittest import mock

import gxw_ladder_reader as reader


LD_M1 = bytes.fromhex("03 00 03 04 90 01 04")


def _note(text: bytes, raw_type: int) -> bytes:
    length = len(text) + 4
    return bytes((length, 0x82, raw_type)) + text + bytes((length,))


def _program(text: bytes, raw_type: int) -> bytes:
    return LD_M1 + _note(text, raw_type)


class TypedAsciiNoteTests(unittest.TestCase):
    def test_verified_ascii_lengths_and_both_raw_types(self) -> None:
        samples = tuple(b"A" * length for length in range(1, 33))
        for text in samples:
            for raw_type, subtype in ((1, "s"), ((len(text) + 5) // 2, "i")):
                with self.subTest(text=text, raw_type=raw_type):
                    record, = reader.typed_note_records(
                        _program(text, raw_type), ascii_types=True)
                    self.assertEqual(text.decode("ascii"), record["text"])
                    self.assertEqual(f"0x{raw_type:02x}", record["raw_type"])
                    self.assertEqual(subtype, record["subtype"])
                    self.assertEqual({"instruction": "LD", "operands": ["M1"]},
                                     record["attachment"])

    def test_default_mapping_remains_same_text_only(self) -> None:
        for text in (b"A", b"Hi", b"ABCDEFGH", b"DIFFERENT", b"0123456789"):
            with self.subTest(text=text):
                self.assertIsNone(reader.typed_note_records(
                    _program(text, 1))[0]["subtype"])
        for raw_type, expected in ((1, "s"), (7, "i")):
            with self.subTest(raw_type=raw_type):
                self.assertEqual(expected, reader.typed_note_records(
                    _program(b"SAME TEXT", raw_type))[0]["subtype"])

    def test_unknown_length_and_non_ascii_remain_untyped(self) -> None:
        for text in (b"A" * 33, b"ABC\x7fEFGH", b"ABC\x80EFGH"):
            for raw_type in (1, (len(text) + 5) // 2):
                with self.subTest(text=text, raw_type=raw_type):
                    record, = reader.typed_note_records(
                        _program(text, raw_type), ascii_types=True)
                    self.assertIsNone(record["subtype"])

    def test_opt_in_records_project_to_expected_csv_note_text(self) -> None:
        for raw_type, expected in ((1, '"*Hi"'), (3, '"Hi"')):
            with self.subTest(raw_type=raw_type):
                program = _program(b"Hi", raw_type)
                rows, _, _ = reader.pou_rows(program)
                records = reader.typed_note_records(program, ascii_types=True)
                csv = reader.gx_csv_for_pou("P1", rows, "P1", "Q", records)
                self.assertIn(expected, csv)

    def test_wrong_type_and_damaged_frame_are_not_promoted(self) -> None:
        text = b"ABCDEFGH"
        valid = _note(text, 1)
        for frame in (
            _note(text, 2),
            valid[:-1] + b"\x00",
            valid[:-2],
        ):
            with self.subTest(frame=frame):
                self.assertEqual([], reader.typed_note_records(
                    LD_M1 + frame, ascii_types=True))

    def test_missing_or_mismatched_attachment_still_rejected(self) -> None:
        frame = _note(b"A", 1)
        with self.assertRaisesRegex(ValueError, "no preceding instruction"):
            reader.typed_note_records(frame, ascii_types=True)
        with mock.patch.object(reader, "pou_rows", return_value=(
            [("LD", "M1", ""), ("__NOTE__", "B", "")], set(), set())):
            with self.assertRaisesRegex(ValueError, "text does not match"):
                reader.typed_note_records(LD_M1 + frame, ascii_types=True)

    def test_leading_plain_statement_is_not_dropped(self) -> None:
        for text in (b"ASCII FIRST", b"A", b"BEFORE \x97 AFTER"):
            length = len(text) + 4
            frame = bytes((length, 0x80, (length + 1) // 2)) + text + bytes((length,))
            rows, unknown_i, unknown_d = reader.pou_rows(b"\x00" * 16 + frame + LD_M1)
            self.assertEqual([("__STMT__", text.decode("cp1252"), ""), ("LD", "M1", ""),
                              ("END", "", "")], rows)
            self.assertFalse(unknown_i or unknown_d)

    def test_malformed_leading_statement_is_not_promoted(self) -> None:
        text = b"ASCII FIRST"
        length = len(text) + 4
        frame = bytes((length, 0x80, (length + 1) // 2)) + text + bytes((length,))
        for invalid, diagnostic in ((frame[:-1] + b"\x00", False),
                                    (frame[:2] + b"\x01" + frame[3:], True),
                                    (frame[:3] + b"\x01" + frame[4:], True)):
            with self.subTest(invalid=invalid.hex()):
                rows, unknown, _ = reader.pou_rows(b"\x00" * 16 + invalid + LD_M1)
                self.assertEqual([("LD", "M1", ""), ("END", "", "")], rows[-2:])
                self.assertNotIn("__STMT__", [row[0] for row in rows])
                if diagnostic:
                    self.assertEqual({"<i:text:statement>"}, unknown)
                    self.assertEqual(("<i:text:statement>", "", ""), rows[0])


if __name__ == "__main__":
    unittest.main()
