"""Independent synthetic counterexamples for section and diagnostic integrity."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gxw_ladder_reader as reader
import gxw_reference_ir as reference

LD = bytes.fromhex("03 00 03 04 90 00 04")
END = bytes.fromhex("04 34 02 04")
DMOV = bytes.fromhex("05 4c 03 01 05 07 e9 34 02 04 00 07 04 a8 0a 04")


def project_rows(body):
    rows, ui, ud = reader.pou_rows(body)
    return reference.project_rows([
        {"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
         "rows": rows, "unknown_instructions": sorted(ui), "unknown_devices": sorted(ud)}
    ], input_sha256="a" * 64)


class ReaderReliabilityTests(unittest.TestCase):
    def test_dmov_marker_inside_constant_preserves_sequence_and_csv(self):
        body = LD + DMOV + LD + END
        expected = [("LD", "M0"), ("DMOV", "K262708 D10"), ("LD", "M0"), ("END", "")]
        self.assertEqual(expected, reader.decode_program(body))
        rows, ui, ud = reader.pou_rows(body + b"trailing metadata")
        self.assertEqual(expected, [(op, operands) for op, operands, _ in rows])
        self.assertFalse(ui or ud)
        csv = reader.gx_csv_for_pou("MAIN", rows, "SYNTHETIC", "QCPU")
        self.assertIn('"K262708"', csv)
        self.assertIn('"D10"', csv)
        self.assertEqual(body, reader.program_section(body + b"trailing metadata"))

    def test_note_attachment_uses_same_complete_section(self):
        note = bytes.fromhex("09 82 05") + b"READY" + b"\x09"
        body = LD + DMOV + note + LD + END
        records = reader.typed_note_records(body, framed_types=True)
        self.assertEqual(["READY"], [record["text"] for record in records])
        self.assertEqual({"instruction": "DMOV", "operands": ["K262708", "D10"]},
                         records[0]["attachment"])

    def test_separator_before_operand_cannot_create_a_false_frame(self):
        command = bytes.fromhex("05 4c 03 01 05 04 07 e9 04 34 02 04 07 04 a8 0a 04")
        body = LD + command + LD + END
        expected = [("LD", "M0"), ("DMOV", "K67253252 D10"), ("LD", "M0"), ("END", "")]
        self.assertEqual(expected, reader.decode_program(body))
        self.assertEqual(expected, [(op, operands) for op, operands, _ in reader.pou_rows(body)[0]])

    def test_unknown_operand_descriptor_cannot_create_a_false_trailer(self):
        command = bytes.fromhex("05 4c 03 01 05 07 ff 04 34 02 04 07 04 a8 0a 04")
        body = LD + command + LD + END
        self.assertEqual(body, reader.program_section(body))
        rows, _, ud = reader.pou_rows(body)
        self.assertTrue(ud)
        self.assertEqual("DMOV", rows[1][0])
        self.assertIn("D10", rows[1][1])
        self.assertEqual(("LD", "M0", ""), rows[-2])
        self.assertEqual("PARTIAL", project_rows(body)["analysis"]["state"])

    def test_short_text_frames_remain_command_boundaries(self):
        header = bytes.fromhex("0c 71 00 00 00") + b"BUFSND" + bytes((12,))
        for marker, kind in ((0x80, "__STMT__"), (0x82, "__NOTE__")):
            for width in (5, 6, 7):
                with self.subTest(marker=marker, width=width):
                    frame = bytes((width, marker, (width + 1) // 2)) + b"A" * (width - 4) + bytes((width,))
                    self.assertEqual(-1, reader._scan_to_operand(frame, 0, len(frame)))
                    body = LD + header + bytes.fromhex("04 a8 0a 04") + frame + LD + END
                    rows, _, _ = reader.pou_rows(body)
                    self.assertIn((kind, "A" * (width - 4), ""), rows)
                    self.assertEqual(("LD", "M0", ""), rows[-2])

    def test_balanced_invalid_text_subtype_retains_diagnostic(self):
        for marker, kind in ((0x80, "statement"), (0x82, "note")):
            for subtype in (4, 5):
                for prefix in (b"", LD):
                    with self.subTest(marker=marker, subtype=subtype, prefix=prefix):
                        framed = bytes((8, marker, subtype)) + END + bytes((8,))
                        body = prefix + framed + LD + END
                        self.assertEqual(body, reader.program_section(body))
                        rows, ui, _ = reader.pou_rows(body)
                        self.assertIn(f"<i:text:{kind}>", ui)
                        self.assertEqual(("LD", "M0", ""), rows[-2])
                        self.assertEqual("PARTIAL", project_rows(body)["analysis"]["state"])

    def test_framed_marker_and_unframed_or_damaged_boundary(self):
        # Control bytes make this text unsupported, but cannot become a trailer.
        framed = bytes.fromhex("08 80 04 34 02 04 41 08")
        body = LD + framed + LD + END
        self.assertEqual(body, reader.program_section(body + b"metadata"))
        rows, ui, _ = reader.pou_rows(body)
        self.assertIn("<i:text:statement>", ui)
        self.assertEqual(("LD", "M0", ""), rows[-2])
        with self.assertRaisesRegex(ValueError, "boundary"):
            reader.program_section(LD + bytes.fromhex("34 02 04") + LD)
        with self.assertRaisesRegex(ValueError, "boundary"):
            reader.program_section(LD + bytes.fromhex("07 e9 34 02 04 00 06") + END)
        for marker in (0x80, 0x82):
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, "boundary"):
                reader.program_section(LD + bytes((5, marker, 3, 0x41, 7)) + END)

    def test_unknown_operandless_instruction_is_partial_independently(self):
        result = project_rows(LD + bytes.fromhex("04 02 02 04 00 00 00"))
        self.assertEqual("PARTIAL", result["analysis"]["state"])
        self.assertEqual(1, result["coverage"]["unknown_instructions"])
        self.assertEqual(0, result["coverage"]["unknown_operands"])
        self.assertTrue(result["diagnostics"])
        direct = reference.project_rows([
            {"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
             "rows": [("<i:04:02:operand>", "", "")]}
        ], input_sha256="a" * 64)
        self.assertEqual("PARTIAL", direct["analysis"]["state"])

    def test_known_operandless_and_dynamic_keep_complete(self):
        result = project_rows(LD + bytes.fromhex("02 02") + END)
        self.assertEqual("COMPLETE", result["analysis"]["state"])
        dynamic = reference.project_rows([
            {"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
             "rows": [("MOV", "D0Z1 D10", ""), ("END", "", "")]}
        ], input_sha256="a" * 64)
        self.assertEqual("COMPLETE", dynamic["analysis"]["state"])
        self.assertEqual("DYNAMIC", dynamic["occurrences"][0]["operands"][0]["coverage"]["state"])

    def test_edge_headers_and_each_operand_cut_at_eof_and_recovery(self):
        operand = bytes.fromhex("05 90 01 00 05")
        self.assertEqual(12, len(reader.EDGE04))
        for opcode in reader.EDGE04:
            for mode in (2, 3, 4):
                for cut in range(len(operand)):
                    with self.subTest(opcode=opcode, mode=mode, cut=cut):
                        damaged = LD + bytes((4, opcode, mode, 4)) + operand[:cut]
                        rows, ui, _ = reader.pou_rows(damaged)
                        self.assertIn(f"<i:04:{opcode:02x}:operand>", ui)
                        self.assertEqual("PARTIAL", project_rows(damaged)["analysis"]["state"])
                        rows, ui, _ = reader.pou_rows(damaged + LD + END)
                        self.assertIn(("LD", "M0", ""), rows[2:])
                        self.assertEqual(("END", "", ""), rows[-1])

    @unittest.skipUnless(__import__("os").name == "nt", "synthetic CFB creation uses Windows COM")
    def test_file_backed_build_binds_correct_digest_and_diagnostics(self):
        from test_single_command import project, res
        for body, state in ((LD + DMOV + LD + END, "COMPLETE"),
                            (LD + bytes.fromhex("04 02 02 04 00 00 00") + END, "PARTIAL")):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                source = project(Path(temporary), body)
                original = source.read_bytes()
                report = reference.build(source)
                self.assertEqual(state, report["analysis"]["state"])
                self.assertEqual(original, source.read_bytes())
                expected_section = res("P1", body, None)[:58 + len(body)]
                self.assertEqual(hashlib.sha256(expected_section).hexdigest(),
                                 report["occurrences"][0]["provenance"]["source_digest"])
                if state == "COMPLETE":
                    self.assertEqual(["LD", "DMOV", "LD", "END"],
                                     [row["record"]["opcode"] for row in report["occurrences"]])


if __name__ == "__main__":
    unittest.main()
