"""Synthetic source-text and complete operand-frame regressions."""
import unittest

import gxw_ladder_reader as reader
import gxw_reference_ir as reference


LD = bytes.fromhex("03 00 03 04 90 00 04")


def text_frame(text, marker, encoding="cp949", subtype=None):
    raw = text.encode(encoding)
    length = len(raw) + 4
    return bytes((length, marker, (length + 1) // 2 if subtype is None else subtype)) + raw + bytes((length,))


class SourcePouTextTests(unittest.TestCase):
    def test_high_speed_timer_preserves_word_preset_and_next_command(self):
        # Synthetic timers and set values; no project-derived fixture.
        header = bytes.fromhex("04 22 04 04")
        following = bytes.fromhex("03 1b 03")
        for coil, expected_coil in (("04 c2 07 04", "T7"), ("04 c8 05 04", "ST5")):
            for preset, expected_preset in (("04 a8 31 04", "D49"), ("04 e8 14 04", "K20")):
                with self.subTest(coil=expected_coil, preset=expected_preset):
                    rows, unknown_i, unknown_d = reader.pou_rows(
                        LD + header + bytes.fromhex(coil + " " + preset) + following + LD)
                    self.assertEqual([("LD", "M0", ""), ("OUTH", f"{expected_coil} {expected_preset}", ""),
                                      ("MRD", "", ""), ("LD", "M0", ""), ("END", "", "")], rows)
                    self.assertFalse(unknown_i or unknown_d)

    def test_high_speed_timer_never_consumes_following_instruction_as_preset(self):
        incomplete = bytes.fromhex("04 22 04 04 04 c2 07 04")
        for following, expected in (("03 1b 03", ("MRD", "", "")),
                                    ("04 24 02 04 04 90 01 04", ("RST", "M1", "")),
                                    ("04 22 04 04 04 c2 08 04 04 e8 14 04", ("OUTH", "T8 K20", ""))):
            rows, unknown_i, _ = reader.pou_rows(LD + incomplete + bytes.fromhex(following) + LD)
            self.assertEqual([("LD", "M0", ""), ("<i:04:22:operand>", "T7", ""), expected,
                              ("LD", "M0", ""), ("END", "", "")], rows)
            self.assertIn("<i:04:22:operand>", unknown_i)

    def test_high_speed_timer_unknown_and_truncated_preset_fail_closed(self):
        header = bytes.fromhex("04 22 04 04 04 c2 07 04")
        for preset in ("04 ff 01 04", "05 a8 01", "04 f0 02 04"):
            rows, unknown_i, _ = reader.pou_rows(LD + header + bytes.fromhex(preset) + bytes.fromhex("04 24 02 04 04 90 01 04") + LD)
            self.assertIn("<i:04:22:operand>", unknown_i)
            self.assertIn(("RST", "M1", ""), rows)
            self.assertEqual(("LD", "M0", ""), rows[-2])

    def test_buffer_transfer_exact_modes_and_four_operands(self):
        operands = bytes.fromhex("04 ea 06 04 05 ea 00 06 05 05 a8 bc 02 05 04 e8 14 04")
        for header, opcode in (("05 56 05 00 05", "FROM"),
                               ("06 56 06 00 02 06", "FROMP"),
                               ("06 56 06 02 02 06", "TOP")):
            command = bytes.fromhex(header) + operands
            for prefix in (b"", LD):
                rows, unknown_i, unknown_d = reader.pou_rows(prefix + command + LD)
                index = bool(prefix)
                self.assertEqual((opcode, "H6 H600 D700 K20", ""), rows[index])
                self.assertEqual(("LD", "M0", ""), rows[index + 1])
                self.assertFalse(unknown_i or unknown_d)

    def test_buffer_transfer_rejects_header_short_extra_and_unknown_operand(self):
        header = bytes.fromhex("06 56 06 00 02 06")
        operands = bytes.fromhex("04 ea 06 04 04 ea a8 04 05 a8 7a 03 05 04 e8 01 04")
        cases = [bytes.fromhex("06 56 06 00 03 06") + operands,
                 bytes.fromhex("05 56 05 02 05") + operands,
                 header + operands[:-4], header + operands + bytes.fromhex("04 e8 02 04"),
                 header + operands + bytes.fromhex("04 ff 01 04"),
                 header + operands + bytes.fromhex("05 a8 01"),
                 header + operands.replace(bytes.fromhex("05 a8"), bytes.fromhex("05 ff"))]
        for command in cases:
            rows, unknown_i, _ = reader.pou_rows(LD + command + LD)
            self.assertIn("<i:56:buffer-transfer>", unknown_i)
            self.assertNotIn("FROMP", [row[0] for row in rows])
            self.assertEqual(("LD", "M0", ""), rows[-2])

    def test_buffer_transfer_eof_and_leading_malformed_keep_coverage(self):
        header = bytes.fromhex("06 56 06 00 02 06")
        operands = bytes.fromhex("04 ea 06 04 04 ea a8 04 05 a8 7a 03 05 04 e8 01 04")
        self.assertEqual(("FROMP", "H6 H0A8 D890 K1", ""), reader.pou_rows(header + operands)[0][0])
        for cut in range(2, len(header + operands)):
            command = (header + operands)[:cut]
            rows, unknown_i, _ = reader.pou_rows(command + LD)
            self.assertIn("<i:56:buffer-transfer>", unknown_i, cut)
            self.assertEqual(("LD", "M0", ""), rows[-2], cut)
            if cut >= 3:
                reader.pou_rows(command)  # Truncated EOF must never raise.

        coil = bytes.fromhex("04 20 02 04 04 90 00 04")
        rows, unknown_i, _ = reader.pou_rows(LD + header + operands[:-4] + bytes.fromhex("04 f0 06 04") + coil)
        self.assertIn("<i:56:buffer-transfer>", unknown_i)
        self.assertIn(("OUT", "M0", ""), rows)

    def test_unicode_and_byte_length_note_binding(self):
        text = "설비 준비"
        for subtype, expected in ((1, "s"), ((len(text.encode('cp949')) + 5) // 2, "i")):
            program = LD + text_frame(text, 0x82, subtype=subtype)
            rows, unknown_i, unknown_d = reader.pou_rows(program, text_encoding="cp949")
            self.assertEqual(("__NOTE__", text, ""), rows[1])
            note, = reader.typed_note_records(program, text_encoding="cp949", framed_types=True)
            self.assertEqual(expected, note["subtype"])
            self.assertEqual(len(text.encode("cp949")), note["encoded_length"])
            self.assertEqual(text.encode("cp949").hex(), note["raw_text_hex"])
            self.assertEqual({"instruction": "LD", "operands": ["M0"]}, note["attachment"])
            self.assertFalse(unknown_i or unknown_d)

    def test_auto_policy_preserves_korean_and_cp1252_round_trip(self):
        for text, encoding in (("[Title] 프로그램 설정", "cp949"), ("BEFORE \u2014 AFTER", "cp1252")):
            program = text_frame(text, 0x80, encoding=encoding) + LD
            self.assertEqual(("__STMT__", text, ""), reader.pou_rows(program, text_encoding="auto")[0][0])
        with self.assertRaises(ValueError):
            reader._decode_pou_text(b"\x81", "auto")
        with self.assertRaises(ValueError):
            reader._decode_pou_text(b"plain", "unsupported")

    def test_long_framed_note_does_not_invent_character_cap(self):
        text = "준비" * 40
        program = LD + text_frame(text, 0x82)
        note, = reader.typed_note_records(program, text_encoding="cp949", framed_types=True)
        self.assertEqual(text, note["text"])
        self.assertEqual("i", note["subtype"])
        self.assertIsNone(reader.typed_note_records(program, text_encoding="cp949", ascii_types=True)[0]["subtype"])

    def test_complete_coil_operand_frames_do_not_emit_inner_false_opcodes(self):
        for op, mnemonic in ((0x20, "OUT"), (0x23, "SET"), (0x24, "RST")):
            for frame in (bytes.fromhex("05 93 19 03 05"), bytes.fromhex("06 93 19 03 01 06"), bytes.fromhex("07 93 ff ff ff ff 07")):
                program = LD + bytes((4, op, 2, 4)) + frame + LD
                rows, unknown_i, unknown_d = reader.pou_rows(program)
                value = int.from_bytes(frame[2:-1], "little")
                self.assertEqual([( "LD", "M0", ""), (mnemonic, f"F{value}", ""), ("LD", "M0", ""), ("END", "", "")], rows)
                self.assertFalse(unknown_i or unknown_d)

    def test_pulse_direct_output_and_noops_preserve_every_instruction(self):
        operand = bytes.fromhex("04 a8 0a 04 04 e8 01 04 04 a8 0b 04")
        program = (LD + bytes.fromhex("06 49 04 01 02 06") + operand
                   + LD + bytes.fromhex("06 49 04 03 02 06") + operand
                   + LD + bytes.fromhex("04 20 03 04 04 f0 06 04 04 a3 04 04")
                   + bytes.fromhex("02 02 03 38 03 04"))
        rows, unknown_i, unknown_d = reader.pou_rows(program)
        self.assertEqual([("LD", "M0", ""), ("+P", "D10 K1 D11", ""),
                          ("LD", "M0", ""), ("-P", "D10 K1 D11", ""),
                          ("LD", "M0", ""), ("OUT", "DY4Z6", ""),
                          ("NOP", "", ""), ("NOPLF", "", ""), ("END", "", "")], rows)
        self.assertFalse(unknown_i or unknown_d)

    def test_reference_device_radix_and_finite_float(self):
        operand = reference.parse_operand("DY0A4Z6", 0)
        self.assertEqual(("decoded", "DY", 0xA4, "bit"),
                         (operand["status"], operand["device"]["family"], operand["device"]["address"], operand["device"]["unit"]))
        module = reference.parse_operand("UA\\G4294967296", 0)
        self.assertEqual((10, 4294967296), (module["device"]["module"], module["device"]["address"]))
        for token, value in (("E4.5", 4.5), ("E-1e-3", -.001), ("E4", 4.0)):
            item = reference.parse_operand(token, 0)
            self.assertEqual("decoded", item["status"])
            self.assertEqual(value, item["constant"]["value"])
            self.assertEqual(token, item["raw_token"])
        for token in ("Enan", "Einf", "E1e999", "E1_0", "E 1"):
            self.assertEqual("unknown", reference.parse_operand(token, 0)["status"])
        for number in (2, 10, 16, 255):
            program = LD + bytes((4, 0x20, 3, 4, 4, 0xF8, number, 4, 4, 0xAB, 0, 4))
            rows, unknown_i, unknown_d = reader.pou_rows(program)
            item = reference.parse_operand(rows[1][1], 0)
            self.assertEqual(number, item["device"]["module"])
            self.assertEqual(0, item["device"]["address"])
            self.assertFalse(unknown_i or unknown_d)

    def test_new_leading_commands_are_not_dropped(self):
        pulse = bytes.fromhex("06 49 04 01 02 06 04 a8 0a 04 04 e8 01 04 04 a8 0b 04")
        for command, expected in ((bytes.fromhex("02 02"), ("NOP", "", "")),
                                  (bytes.fromhex("03 38 03"), ("NOPLF", "", "")),
                                  (pulse, ("+P", "D10 K1 D11", ""))):
            rows, unknown_i, unknown_d = reader.pou_rows(command + LD)
            self.assertEqual(expected, rows[0])
            self.assertEqual(("LD", "M0", ""), rows[1])
            self.assertFalse(unknown_i or unknown_d)

    def test_short_pulse_does_not_consume_next_modified_coil(self):
        program = (LD + bytes.fromhex("06 49 04 01 02 06 04 a8 0a 04 04 e8 01 04")
                   + bytes.fromhex("04 20 03 04 04 f0 06 04 04 a3 04 04"))
        rows, unknown_i, _ = reader.pou_rows(program)
        self.assertEqual(("<i:06:49:operand>", "D10 K1", ""), rows[1])
        self.assertEqual(("OUT", "DY4Z6", ""), rows[2])
        self.assertEqual({"<i:06:49:operand>"}, unknown_i)

    def test_sb_and_retentive_timer_source_codes_have_no_address_ceiling(self):
        for code, family in ((0xA1, "SB"), (0xC8, "ST")):
            for value in (0, 255, 2048, 0xFFFFFFFF):
                frame = bytes((7, code)) + value.to_bytes(4, "little") + bytes((7,))
                rows, unknown_i, unknown_d = reader.pou_rows(LD + bytes((3, 0x0C, 3)) + frame)
                expected = family + (reader._cmt_hex(value) if family == "SB" else str(value))
                self.assertEqual(("AND", expected, ""), rows[1])
                self.assertFalse(unknown_i or unknown_d)
                self.assertEqual("decoded", reference.parse_operand(expected, 0)["status"])

    def test_leading_wide_operand_is_consumed_before_inner_noop_bytes(self):
        for header, mnemonic in ((bytes.fromhex("04 20 02 04"), "OUT"),
                                 (bytes.fromhex("03 00 03"), "LD")):
            rows, unknown_i, unknown_d = reader.pou_rows(header + bytes.fromhex("07 93 02 02 00 00 07") + LD)
            self.assertEqual((mnemonic, "F514", ""), rows[0])
            self.assertEqual(("LD", "M0", ""), rows[1])
            self.assertFalse(unknown_i or unknown_d)


if __name__ == "__main__":
    unittest.main()
