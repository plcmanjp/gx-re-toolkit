"""Independently generated interrupt-control grammar fixtures, no project data."""
import unittest
from gx3_fx5_profile.decoder import MiningRequired, _decode_mil
from gx3_fx5_profile.opcode_signatures import UnknownOpcodeSignature, lookup_mnemonic, mil_stream
from test_mil_pointer_control import combined, contact, pointer_control, terminator


class InterruptControlMilTests(unittest.TestCase):
    def test_zero_operand_instructions(self):
        for marker in ('EI', 'DI', 'IRET'):
            with self.subTest(marker=marker):
                self.assertEqual(_decode_mil(terminator(marker), 1), [
                    dict(kind='instruction', opcode=marker, operands=[], text=None)])

    def test_i_and_p_declarations_keep_their_own_tag(self):
        for ordinal in (0, 7, 43, 4095):
            for tag in ('I', 'P'):
                with self.subTest(ordinal=ordinal, tag=tag):
                    data = pointer_control('Pointer', ordinal).replace('Pointer:P:', f'Pointer:{tag}:')
                    self.assertEqual(_decode_mil(data, 1), [
                        dict(kind='instruction', opcode=f'{tag}{ordinal}', operands=[], text=None)])

    def test_combined_interrupt_order_preserves_existing_instructions(self):
        declaration = pointer_control('Pointer', 7).replace('Pointer:P:', 'Pointer:I:')
        data = combined(contact(ordinal=3), terminator('EI'), contact(ordinal=4),
                        terminator('DI'), terminator('FEND'), declaration,
                        contact(ordinal=5), terminator('IRET'), terminator('END'))
        self.assertEqual([(r['opcode'], r['operands']) for r in _decode_mil(data, 9)], [
            ('LD', ['M3']), ('EI', []), ('LD', ['M4']), ('DI', []), ('FEND', []),
            ('I7', []), ('LD', ['M5']), ('IRET', []), ('END', [])])
        with self.assertRaises(MiningRequired):
            _decode_mil(data, 8)

    def test_call_and_cj_do_not_accept_interrupt_tag(self):
        for marker in ('CALL', 'CJ'):
            data = pointer_control(marker, 7).replace(f'{marker}:P:', f'{marker}:I:')
            with self.subTest(marker=marker):
                signature = mil_stream(data)[0][1]
                with self.assertRaises(UnknownOpcodeSignature):
                    lookup_mnemonic(signature)
                with self.assertRaises(MiningRequired):
                    _decode_mil(data, 1)

    def test_i_declaration_bad_tag_operand_pulse_and_extra_fields(self):
        data = pointer_control('Pointer', 7).replace('Pointer:P:', 'Pointer:I:')
        mutations = [('Pointer:I:', 'Pointer:D:'), ('Pointer:I:', 'Pointer:I:M:'),
                     ('vt=p', 'vt=A16'), ('s=#', 's=0'), ('op=#', 'op=0'),
                     ('vt=nn', 'vt=nx'), ('a=7', 'a=-1'),
                     ('op=#:as=', 'op=#:ct=p:as='),
                     ('a=7:vt=nn', 'a=7:vt=nn:extra=1'),
                     ('d{s=#:a=7:vt=nn}', 'c{s=#:v=7:si=s}')]
        for old, new in mutations:
            with self.subTest(mutation=new), self.assertRaises(MiningRequired):
                _decode_mil(data.replace(old, new), 1)
        for replacement in ('', ':as=[d{s=#:a=7:vt=nn}:d{s=#:a=8:vt=nn}]'):
            with self.assertRaises(MiningRequired):
                _decode_mil(data.replace(':as=[d{s=#:a=7:vt=nn}]', replacement), 1)

    def test_zero_operand_control_mutations_remain_closed(self):
        for marker in ('EI', 'DI', 'IRET'):
            data = terminator(marker)
            for old, new in [('op=#', 'op=0'), ('ct=a', 'ct=p'),
                             ('ct=a', 'ct=a:extra=1'),
                             ('ct=a', 'ct=a:as=[as{vt=p}]'),
                             (f'{marker}:ms', f'{marker}:I:ms'),
                             ('}}]}', '}:as=[d{s=#:a=7:vt=nn}]}]}')]:
                with self.subTest(marker=marker, mutation=new), self.assertRaises(MiningRequired):
                    _decode_mil(data.replace(old, new), 1)


if __name__ == '__main__':
    unittest.main()
