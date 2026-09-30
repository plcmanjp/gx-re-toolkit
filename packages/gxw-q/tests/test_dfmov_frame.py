"""Synthetic fixed-frame DFMOV source-decoding boundaries."""
import unittest
import gxw_ladder_reader as reader

LD = bytes.fromhex("03 00 03 04 90 00 04")
END = bytes.fromhex("04 34 02 04")
HEADER = bytes.fromhex("05 4c 05 0e 05")
OPERANDS = bytes.fromhex("04 e9 00 04 05 a8 c8 02 05 04 e8 50 04")


class DfmovFrameTests(unittest.TestCase):
    def test_leading_dfmov_is_not_skipped_for_next_contact(self):
        rows, ui, ud = reader.pou_rows(HEADER + OPERANDS + LD + END)
        self.assertEqual(('DFMOV', 'K0 D712 K80'), rows[0][:2])
        self.assertEqual(('LD', 'M0'), rows[1][:2])
        self.assertFalse(ui or ud)

    def test_complete_and_torn_eof_do_not_raise_or_invent_operands(self):
        rows, ui, ud = reader.pou_rows(LD + HEADER + OPERANDS)
        self.assertEqual(('DFMOV', 'K0 D712 K80'), rows[1][:2])
        self.assertFalse(ui or ud)
        for cut in (0, 4, 9, 12):
            with self.subTest(cut=cut):
                rows, ui, _ = reader.pou_rows(LD + HEADER + OPERANDS[:cut])
                self.assertIn('<i:05:4c:0e>', ui)
                self.assertNotIn('DFMOV', [r[0] for r in rows])

    def test_leading_malformed_header_preserves_unknown_and_next_contact(self):
        rows, ui, _ = reader.pou_rows(HEADER[:-1] + b'\x06' + OPERANDS + LD + END)
        self.assertIn('<i:05:4c:0e>', ui)
        self.assertEqual(('LD', 'M0'), rows[-2][:2])

    def test_complete_three_operands_and_next_instruction(self):
        rows, ui, ud = reader.pou_rows(LD + HEADER + OPERANDS + LD + END)
        self.assertEqual([(r[0], r[1]) for r in rows],
                         [('LD', 'M0'), ('DFMOV', 'K0 D712 K80'), ('LD', 'M0'), ('END', '')])
        self.assertFalse(ui or ud)

    def test_incomplete_frame_never_consumes_next_contact(self):
        for cut in (0, 4, 9):
            with self.subTest(cut=cut):
                rows, ui, _ = reader.pou_rows(LD + HEADER + OPERANDS[:cut] + LD + END)
                self.assertIn('<i:05:4c:0e>', ui)
                self.assertEqual(('LD', 'M0'), rows[-2][:2])
                self.assertNotIn('DFMOV', [r[0] for r in rows])

    def test_header_closer_extra_operand_and_torn_operand_are_unknown(self):
        malformed = [HEADER[:-1] + b'\x06' + OPERANDS,
                     HEADER + OPERANDS + bytes.fromhex('04 e8 01 04'),
                     HEADER + OPERANDS[:-1] + b'\x05']
        for candidate in malformed:
            with self.subTest(candidate=candidate.hex()):
                rows, ui, _ = reader.pou_rows(LD + candidate + END)
                self.assertIn('<i:05:4c:0e>', ui)
                self.assertNotIn('DFMOV', [r[0] for r in rows])

    def test_unobserved_header_mode_is_unknown(self):
        rows, ui, _ = reader.pou_rows(LD + bytes.fromhex('05 4c 04 0e 05') + OPERANDS + END)
        self.assertIn('<i:05:4c:0e>', ui)
        self.assertNotIn('DFMOV', [r[0] for r in rows])


if __name__ == '__main__':
    unittest.main()
