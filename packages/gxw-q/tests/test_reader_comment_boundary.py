"""Synthetic GXW comment and instruction boundary regressions."""

from __future__ import annotations

import struct
import unittest
from unittest import mock

import gxw_ladder_reader as reader


def _range(code: int, address: int, count: int) -> bytes:
    return bytes((code, 0)) + struct.pack("<H", address) + b"\0\0" + struct.pack("<I", count)


def _module_range(module: int, address: int, count: int) -> bytes:
    return b"\xab\xf8" + struct.pack("<HHI", address, module, count)


def _comment(value: str, padding: bytes = b"\0" * 4) -> bytes:
    return struct.pack("<I", len(value) + 1) + value.encode("utf-16le") + b"\0\0" + padding


class CommentBoundaryTests(unittest.TestCase):
    @staticmethod
    def _framed_stream(records, texts):
        header = bytearray(60)
        header[:4] = b"\x1a\x00\x08\x01"
        header[56:58] = b"\x20\x0a"
        struct.pack_into("<H", header, 58, len(records))
        directory = b"".join(struct.pack("<HII", *record) for record in records)
        pool = b"".join(b"\0" * 4 + struct.pack("<I", len(text) + 1)
                        + text.encode("utf-16le") + b"\0\0" for text in texts)
        return bytes(header) + directory + pool

    def test_counted_directory_preserves_all_text_without_chain_heuristics(self):
        records = [(0x90, 0, 2), (0x93, 90000, 1), (0xc8, 70000, 1),
                   (0xa8a8, 0xffffff + 1, 1), (0xf8ab, (0x12 << 16) | 4, 1)]
        texts = ["CONTROL", "123", "", "한글\ntext", "word text", "module buffer"]
        stream = self._framed_stream(records, texts)
        pairs, warning = reader.device_comment_pairs({"synthetic": stream})
        self.assertIsNone(warning)
        self.assertEqual(list(zip(["M0", "M1", "F90000", "ST70000", "D16777216", "U12\\G4"], texts)), pairs)
        section = reader._structured_comment_section(stream)
        self.assertEqual(len(stream), section[2])
        self.assertEqual(50, len(reader._comment_directory_region(stream)))
        self.assertEqual([device for device, _ in pairs], reader.unified_directory(stream))
        self.assertEqual([device for device, _ in pairs[:-1]], reader.comment_directory(stream))
        self.assertEqual(["D16777216"], reader.high_addr_directory(stream))
        self.assertEqual(["U12\\G4"], reader.ug_directory(stream))

    def test_counted_directory_does_not_scan_text_for_range_records(self):
        texts = ["alphaÅa", "MODULE123", "short", "later text"]
        stream = self._framed_stream([(0x90, 100, 4)], texts)
        pairs, warning = reader.device_comment_pairs({"synthetic": stream})
        self.assertIsNone(warning)
        self.assertEqual(list(zip(["M100", "M101", "M102", "M103"], texts)), pairs)

    def test_counted_u_high_code_uses_same_family_table_for_every_directory_api(self):
        stream = self._framed_stream([(0xd8d8, 0x12, 1)], ["module label"])
        self.assertEqual(([('U12', 'module label')], None), reader.device_comment_pairs({'synthetic': stream}))
        for method in (reader.comment_directory, reader.high_addr_directory, reader.unified_directory):
            self.assertEqual(['U12'], method(stream))

    def test_counted_directory_rejects_unknown_duplicate_and_incomplete_records(self):
        cases = [self._framed_stream([(0xffff, 0, 1)], ["unknown"]),
                 self._framed_stream([(0x90, 0, 1), (0x90, 0, 1)], ["one", "two"]),
                 self._framed_stream([(0x90, 0, 2)], ["one"]),
                 self._framed_stream([(0x90, 0, 1)], ["one"])[:-1],
                 self._framed_stream([(0x90, 0, 1)], ["embedded\0null"])]
        for stream in cases:
            with self.subTest(length=len(stream)), self.assertRaises(ValueError):
                reader.device_comment_pairs({"synthetic": stream})

    def test_counted_directory_keeps_resource_budget_independent_of_addresses(self):
        stream = self._framed_stream([(0x90, 0xffffffff, 2)], ["high", "next"])
        pairs, warning = reader.device_comment_pairs({"synthetic": stream})
        self.assertIsNone(warning)
        self.assertEqual(["M4294967295", "M4294967296"], [device for device, _ in pairs])
        with mock.patch.object(reader, "MAX_COMMENT_DIRECTORY_ENTRIES", 1), self.assertRaises(ValueError):
            reader.device_comment_pairs({"synthetic": stream})

    @staticmethod
    def _bit_section(groups):
        body = bytearray()
        for code, module, words in groups:
            body.extend(struct.pack("<HHI", code, module, len(words)))
            for address, comments in words:
                body.extend(struct.pack("<IH", address, len(comments)))
                for bit, text in comments:
                    body.extend(struct.pack("<HH", bit, len(text) + 1))
                    body.extend(text.encode("utf-16le") + b"\0\0")
        return struct.pack("<IIHH", len(body) + 12, 0, 1, len(groups)) + body

    def test_counted_bit_comments_keep_explicit_family_module_and_address(self):
        section = self._bit_section([
            (0xf8ab, 0x12, [(0xffffffff, [(0, "buffer bit"), (15, "last bit")])]),
            (0xa8, 0, [(123456, [(3, "word bit")])]),
            (0xa9, 0, [(70000, [(4, "system bit")])]),
            (0xb4, 0, [(0xabc, [(5, "link bit")])]),
        ])
        expected = [("U12\\G4294967295.0", "buffer bit"),
                    ("U12\\G4294967295.F", "last bit"),
                    ("D123456.3", "word bit"), ("SD70000.4", "system bit"),
                    ("W0ABC.5", "link bit")]
        self.assertEqual(expected, reader._structured_bit_comment_pairs(section))
        stream = self._framed_stream([(0x90, 0, 1)], ["normal"]) + section
        self.assertEqual(([("M0", "normal")] + expected, None),
                         reader.device_comment_pairs({"synthetic": stream}))

    def test_counted_bit_comments_reject_partial_duplicate_unknown_and_trailing_data(self):
        valid = self._bit_section([(0xf8ab, 7, [(123, [(1, "one")])])])
        cases = [valid[:-1], valid + b"extra",
                 self._bit_section([(0xffff, 0, [(1, [(0, "bad")])])]),
                 self._bit_section([(0xa8, 7, [(1, [(0, "bad")])])]),
                 self._bit_section([(0xa8, 0, [(1, [(0, "one"), (0, "two")])])]),
                 self._bit_section([(0xa8, 0, [(1, [(16, "bad")])])]),
                 self._bit_section([(0xa8, 0, [(1, [(0, "embedded\0null")])])])]
        for section in cases:
            with self.subTest(length=len(section)), self.assertRaises(ValueError):
                reader._structured_bit_comment_pairs(section)

    def test_counted_normal_and_bit_comments_share_total_budget(self):
        stream = (self._framed_stream([(0x90, 0, 1)], ["normal"])
                  + self._bit_section([(0xa8, 0, [(1, [(0, "bit")])])]))
        with mock.patch.object(reader, "MAX_COMMENT_DIRECTORY_ENTRIES", 1), self.assertRaisesRegex(ValueError, "entry budget"):
            reader.device_comment_pairs({"synthetic": stream})

    def test_counted_bit_only_and_empty_streams_do_not_use_legacy_fallback(self):
        empty = self._framed_stream([], [])
        bits = self._bit_section([(0xa8, 0, [(1, [(0, "one")])])])
        self.assertEqual(([("D1.0", "one")], None), reader.device_comment_pairs({"synthetic": empty + bits}))
        self.assertEqual(([], None), reader.device_comment_pairs({"synthetic": empty}))
        with self.assertRaises(ValueError):
            reader.device_comment_pairs({"synthetic": empty + bits[:-1]})

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

    @staticmethod
    def _addressed_u_stream(runs: tuple[tuple[int, int], ...],
                            labels: tuple[str, ...]) -> bytes:
        directory = _range(0x90, 0, 30) + _range(0x90, 30, 30)
        u_directory = b"".join(_range(0xD8, start, count) for start, count in runs)
        first = b"".join(_comment(f"first {i}") for i in range(30))
        gap = b"".join(_comment(label) for label in labels)
        second = b"".join(_comment(f"second {i}") for i in range(30))
        return directory + u_directory + first + gap + second

    def test_bounded_u_directory_binds_sparse_append_and_merged_ranges(self) -> None:
        cases = (
            (((0, 1), (2, 1)), ("MODA001", "MODC003"), ("U0", "U2")),
            (((0, 1), (2, 2)), ("MODA001", "MODC003", "MODD004"),
             ("U0", "U2", "U3")),
            (((0, 4),), ("MODA001", "MODB002", "MODC003", "MODD004"),
             ("U0", "U1", "U2", "U3")),
        )
        for runs, labels, devices in cases:
            with self.subTest(runs=runs):
                stream = self._addressed_u_stream(runs, labels)
                pairs, warning = reader.device_comment_pairs({"synthetic": stream})
                self.assertIsNone(warning)
                self.assertEqual(60 + len(labels), len(pairs))
                self.assertEqual(list(zip(devices, labels)), pairs[-len(labels):])
                self.assertEqual(("M30", "second 0"), pairs[30])

    def test_bounded_u_directory_rejects_missing_duplicate_out_of_range_and_ambiguous(self) -> None:
        cases = (
            (((0, 1),), ("MODA001", "MODC003")),
            (((0, 1), (0, 1)), ("MODA001", "MODC003")),
            (((0, 1), (4, 1)), ("MODA001", "MODC003")),
            (((0, 1), (2, 3)), ("MODA001", "MODC003")),
            (((0, 1), (2, 1)), ("MODA001", "ambiguous text")),
        )
        for runs, labels in cases:
            with self.subTest(runs=runs, labels=labels):
                stream = self._addressed_u_stream(runs, labels)
                _pairs, warning = reader.device_comment_pairs({"synthetic": stream})
                self.assertIsNotNone(warning)

    def test_bounded_u_directory_rejects_outer_label_even_with_matching_count(self) -> None:
        stream = self._addressed_u_stream(((0, 1), (2, 1)), ("MODA001", "MODC003"))
        directory_size = 4 * len(_range(0x90, 0, 30))
        for candidate in (
            stream[:directory_size] + _comment("MODE000") + stream[directory_size:],
            stream + _comment("MODE000"),
        ):
            with self.subTest(candidate_length=len(candidate)):
                _pairs, warning = reader.device_comment_pairs({"synthetic": candidate})
                self.assertIsNotNone(warning)

    def test_bounded_u_directory_rejects_separated_or_malformed_runs(self) -> None:
        stream = self._addressed_u_stream(((0, 1), (2, 1)), ("MODA001", "MODC003"))
        normal_size = 2 * len(_range(0x90, 0, 30))
        first_run_end = normal_size + len(_range(0xD8, 0, 1))
        separated = stream[:first_run_end] + b"noise" + stream[first_run_end:]
        malformed = bytearray(stream)
        malformed[normal_size + 4] = 1
        for candidate in (separated, bytes(malformed)):
            with self.subTest(candidate_length=len(candidate)):
                _pairs, warning = reader.device_comment_pairs({"synthetic": candidate})
                self.assertIsNotNone(warning)

    def test_bounded_u_directory_skips_overlapping_invalid_count_prefix(self) -> None:
        stream = self._addressed_u_stream(((0, 1), (2, 1)), ("MODA001", "MODC003"))
        # A d8-like byte sequence within unrelated prefix data is not a
        # candidate range run when its count exceeds the parser's boundary.
        incidental = b"\xd8\x00\x34\x12\x00\x00" + struct.pack("<I", 0xF0000000)
        pairs, warning = reader.device_comment_pairs({"synthetic": incidental + stream})
        self.assertIsNone(warning)
        self.assertEqual([("U0", "MODA001"), ("U2", "MODC003")], pairs[-2:])

    def test_bounded_u_directory_rejects_multiple_gaps(self) -> None:
        directory = _range(0x90, 0, 90) + _range(0xD8, 0, 2)
        chains = [b"".join(_comment(f"chain {part} item {i}") for i in range(30))
                  for part in range(3)]
        stream = (directory + chains[0] + _comment("MODA001") + chains[1]
                  + _comment("MODB002") + chains[2])
        self.assertIsNotNone(reader.verified_split_comment_chains(
            stream, reader.unified_directory(stream)))
        _pairs, warning = reader.device_comment_pairs({"synthetic": stream})
        self.assertEqual(("UnaddressedModuleLabels", 2), warning)

    def test_module_gap_label_count_obeys_directory_budget(self) -> None:
        gap = _comment("MODA001") + _comment("MODB002")
        with mock.patch.object(reader, "MAX_COMMENT_DIRECTORY_ENTRIES", 1):
            self.assertIsNone(reader._module_label_records(gap))
            self.assertIsNone(reader._unaddressed_module_labels(gap))

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
    def test_all_edge_contacts_at_program_start_and_after_ld(self) -> None:
        edge_names = {
            0x02: "LDP", 0x03: "LDF", 0x04: "LDPI", 0x05: "LDFI",
            0x08: "ORP", 0x09: "ORF", 0x0A: "ORPI", 0x0B: "ORFI",
            0x0E: "ANDP", 0x0F: "ANDF", 0x15: "ANDPI", 0x16: "ANDFI",
        }
        ld = bytes.fromhex("03 00 03 04 90 01 04")
        for opcode, name in edge_names.items():
            frame = bytes((4, opcode, 2, 4, 4, 0x90, 10, 4))
            with self.subTest(opcode=opcode):
                self.assertEqual([(name, "M10"), ("END", "")], reader.decode_program(frame))
                self.assertEqual([(name, "M10"), ("LD", "M1"), ("END", "")],
                                 reader.decode_program(b"\xff\xfe" + frame + ld))
                self.assertEqual([("LD", "M1"), (name, "M10"), ("END", "")],
                                 reader.decode_program(ld + frame))

    def test_edge_contact_requires_complete_operand_frame(self) -> None:
        for bad, token in (
            (bytes.fromhex("04 02 02 04 04 90 0a"), ("<i:04:02:operand>", "")),
            (bytes.fromhex("04 05 02 04 04 90 0d 05"), ("<i:04:05:operand>", "")),
            (bytes.fromhex("04 0a 02 04 04 ff 1a 04"), ("<i:04:0a:operand>", "")),
            (bytes.fromhex("04 0a 02 04 04 f8 01 04 04 ff 1a 04"),
             ("<i:04:0a:operand>", "U1\\<dev:ff>26")),
            (bytes.fromhex("04 0b 02 03 04 90 1b 04"), None),
        ):
            with self.subTest(frame=bad.hex()):
                rows = reader.decode_program(bad)
                self.assertNotIn(("LDP", "M10"), rows)
                self.assertNotIn(("LDFI", "M13"), rows)
                self.assertNotIn(("ORPI", "M26"), rows)
                self.assertNotIn(("ORFI", "M27"), rows)
                if token is not None:
                    self.assertIn(token, rows)

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
