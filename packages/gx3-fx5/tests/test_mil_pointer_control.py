"""Synthetic pointer-control carriers, never proprietary GX projects or exports."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from gx3_fx5_profile.decoder import MiningRequired, SCALAR_TAGS, _decode_mil, _format_operand
from gx3_fx5_profile.opcode_signatures import UnknownOpcodeSignature, lookup_mnemonic, mil_stream
from test_installed_semantics import synthetic_gx3


def pointer_control(marker='CALL', ordinal=255):
    operation = 'cl{op=#:ct=a:as=[as{vt=p}]}' if marker == 'CALL' else 'm{op=#:as=[as{vt=p}]}'
    return f'V1:1:1:{marker}:P:ms{{el=[mc{{op={operation}:as=[d{{s=#:a={ordinal}:vt=nn}}]}}]}}'


def terminator(marker):
    return f'V1:1:1:{marker}:ms{{el=[mc{{op=cl{{op=#:ct=a}}}}]}}'


def contact(tag='M', ordinal=7):
    return f'V1:1:1:A:{tag}:ms{{el=[mc{{op=lct{{op=#:lt=l:ct=a:as=[as{{vt=Abl}}]}}:as=[d{{s=#:a={ordinal}:vt=nn}}]}}]}}'


def mov(source=5, destination=10):
    return f'V1:1:1:MOV:D:D:ms{{el=[mc{{op=cl{{op=#:ct=a:as=[as{{vt=A16}}:as{{vt=A16}}]}}:as=[d{{s=#:a={source}:vt=nn}}:d{{s=#:a={destination}:vt=nn}}]}}]}}'


def combined(*blocks):
    descriptors, items = [], []
    for block in blocks:
        header, body = block.split(':ms{el=[', 1)
        tokens = header.split(':')[1:]
        first = next(i for i, token in enumerate(tokens) if not token.isdigit())
        descriptors.extend(tokens[first:])
        items.append(body[:-2])
    return 'V1:1:1:' + ':'.join(descriptors) + ':ms{el=[' + ':'.join(items) + ']}'


class PointerControlMilTests(unittest.TestCase):
    def assert_closed(self, data, count=1):
        with self.assertRaises(MiningRequired):
            _decode_mil(data, count)

    def test_ordinal_variants_are_syntax_not_cpu_acceptance(self):
        for ordinal in (0, 255, 256, 4095):
            with self.subTest(ordinal=ordinal):
                self.assertEqual(_decode_mil(pointer_control(ordinal=ordinal), 1), [
                    dict(kind='instruction', opcode='CALL', operands=[f'P{ordinal}'], text=None)])
                self.assertEqual(_decode_mil(pointer_control('Pointer', ordinal), 1), [
                    dict(kind='instruction', opcode=f'P{ordinal}', operands=[], text=None)])

    def test_terminators(self):
        for marker in ('FEND', 'RET'):
            self.assertEqual(_decode_mil(terminator(marker), 1), [
                dict(kind='instruction', opcode=marker, operands=[], text=None)])

    def test_complete_record_mutations_remain_closed(self):
        for marker in ('CALL', 'Pointer'):
            data = pointer_control(marker)
            for old, new in (('a=255', 'a=-1'), ('vt=p', 'vt=A16'), ('s=#', 's=0'),
                             ('op=#', 'op=0'), ('vt=nn', 'vt=nx'),
                             ('d{s=#:a=255:vt=nn}', 'c{s=#:v=255:si=s}'),
                             ('a=255:vt=nn', 'a=255:vt=nn:extra=1'),
                             (f'{marker}:P:', f'{marker}:D:'),
                             (f'{marker}:P:', f'{marker}:I:'),
                             (f'{marker}:P:', f'{marker}:P:M:')):
                with self.subTest(marker=marker, mutation=new):
                    self.assert_closed(data.replace(old, new))
            self.assert_closed(data.replace(':as=[d{s=#:a=255:vt=nn}]', ''))
            self.assert_closed(data.replace(':as=[d{s=#:a=255:vt=nn}]', ':as=[d{s=#:a=255:vt=nn}:d{s=#:a=256:vt=nn}]'))
        self.assert_closed(pointer_control().replace('ct=a', 'ct=p'))
        self.assert_closed(pointer_control('Pointer').replace('op=#:as=', 'op=#:ct=a:as='))

    def test_terminator_metadata_operands_and_pulse_remain_closed(self):
        for marker in ('FEND', 'RET'):
            data = terminator(marker)
            for old, new in (('op=#', 'op=0'), ('ct=a', 'ct=p'),
                             ('ct=a', 'ct=a:extra=1'),
                             ('ct=a', 'ct=a:as=[as{vt=p}]'),
                             ('}}]}', '}:as=[d{s=#:a=255:vt=nn}]}]}'),
                             (f'{marker}:ms', f'{marker}:P:ms')):
                with self.subTest(marker=marker, mutation=new):
                    self.assert_closed(data.replace(old, new))

    def test_pointer_is_not_a_generic_scalar_or_unrelated_opcode(self):
        for tag in ('P', 'CALL'):
            self.assertNotIn(tag, SCALAR_TAGS)
            with self.assertRaises(MiningRequired):
                _format_operand([tag], ('scalar', (255,)))
        self.assert_closed(pointer_control().replace('CALL:P:', 'CJ:P:'))
        self.assert_closed(pointer_control('Pointer').replace('Pointer:P:', 'Other:P:'))
        signature = mil_stream(pointer_control().replace('CALL:P:', 'CALL:I:'))[0][1]
        with self.assertRaises(UnknownOpcodeSignature):
            lookup_mnemonic(signature)

    def test_combined_blocks_preserve_full_order(self):
        data = combined(contact(), pointer_control(), contact('SM', 400), mov(),
                        terminator('FEND'), pointer_control('Pointer'),
                        contact('SM', 400), mov(6, 11), terminator('RET'), terminator('END'))
        self.assertEqual([(r['opcode'], r['operands']) for r in _decode_mil(data, 10)], [
            ('LD', ['M7']), ('CALL', ['P255']), ('LD', ['SM400']), ('MOV', ['D5', 'D10']),
            ('FEND', []), ('P255', []), ('LD', ['SM400']), ('MOV', ['D6', 'D11']),
            ('RET', []), ('END', [])])
        self.assert_closed(data, 9)
        self.assert_closed(data, 11)

    def test_control_named_inline_notes_keep_existing_behavior(self):
        for text in ('CALL', 'Pointer', 'FEND', 'RET'):
            for flag in ('i', 's'):
                data = contact().replace(':ms{el=[', f':{text}:{flag}:ms{{el=[')
                data = data[:-2] + ':ma{k=@FE/NOTE:ps=[p{k=STR:v=#}:p{k=NUM:v=#}]}]}'
                with self.subTest(text=text, flag=flag):
                    result = _decode_mil(data, 2)
                    self.assertEqual(result[1], dict(kind='note', opcode=None, operands=[], text=text, note_subtype=flag))

    def test_terminator_and_flag_named_notes_preserve_actual_stream_order(self):
        for marker in ('FEND', 'RET'):
            for text in ('i', 's', 'CALL', 'Pointer', 'FEND', 'RET', 'MOV'):
                for flag in ('i', 's'):
                    data = terminator(marker).replace(':ms{el=[', f':{text}:{flag}:ms{{el=[')
                    data = data[:-2] + ':ma{k=@FE/NOTE:ps=[p{k=STR:v=#}:p{k=NUM:v=#}]}]}'
                    with self.subTest(marker=marker, text=text, flag=flag):
                        self.assertEqual(_decode_mil(data, 2), [
                            dict(kind='instruction', opcode=marker, operands=[], text=None),
                            dict(kind='note', opcode=None, operands=[], text=text, note_subtype=flag)])



class InstalledPointerControlTests(unittest.TestCase):
    def test_unobserved_controls_remain_opaque_in_installed_cli(self):
        cases = [pointer_control().replace('ct=a', 'ct=p'), pointer_control('Pointer', -1),
                 pointer_control().replace('CALL:P:', 'CALL:I:'),
                 terminator('RET').replace('ct=a', 'ct=a:extra=1')]
        for data in cases:
            with self.subTest(data=data), tempfile.TemporaryDirectory(prefix='gx-pointer-closed-') as directory:
                root = Path(directory)
                source = root / 'synthetic-unknown.gx3'
                synthetic_gx3(source, mil_mov=True, mil_source=data)
                before = source.read_bytes()
                output = root / 'ir'
                result = subprocess.run([sys.executable, '-I', '-B', '-m', 'gx3_fx5_parser_toolkit.cli',
                                         str(source), '--phase2-output', str(output)],
                                        cwd=root, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((output / 'neutral-ir.json').read_bytes())
                self.assertEqual(ir['coverage']['record'], dict(total=1, decoded=0, partial=0, unknown=1))
                self.assertEqual(ir['pous'][0]['records'][0]['kind'], 'opaque')
                self.assertTrue(any(r['finding_code'] == 'MINING_REQUIRED' for r in ir['pous'][0]['findings']))
                self.assertEqual(source.read_bytes(), before)

    def test_installed_program_steps_coverage_and_continuations(self):
        blocks = [(combined(contact(), pointer_control()), [2, 3]),
                  (combined(contact('SM', 400), mov()), [2, 4]),
                  (terminator('FEND'), [1]),
                  (combined(pointer_control('Pointer'), contact('SM', 400), mov(6, 11)), [2, 2, 4]),
                  (terminator('RET'), [1]), (terminator('END'), [1])]
        with tempfile.TemporaryDirectory(prefix='gx-pointer-') as directory:
            root = Path(directory)
            source = root / 'synthetic-pointer.gx3'
            synthetic_gx3(source, mil_mov=True)
            with zipfile.ZipFile(source) as archive:
                entries = {name: archive.read(name) for name in archive.namelist()}
            for entry, table, ddl in (
                ('SYN_MilDB.db', 'MIL', 'CREATE TABLE MIL(id TEXT,pos REAL,data TEXT)'),
                ('SYN_LDDB.db', 'LadderBlocks', 'CREATE TABLE LadderBlocks(id TEXT,pos REAL,blocktype INTEGER,data TEXT)'),
                ('1_StepInfo.db', 'T_Step', 'CREATE TABLE T_Step(Pos INTEGER,BlockID TEXT,MilID TEXT,StepSize INTEGER)')):
                db = sqlite3.connect(':memory:')
                try:
                    db.execute(ddl)
                    if table == 'T_Step':
                        db.execute('CREATE TABLE T_Block(Pos REAL,BlockID TEXT)')
                    position = 0
                    for index, (data, widths) in enumerate(blocks):
                        block_id = f'block-{index}'
                        if table == 'MIL':
                            db.execute('INSERT INTO MIL VALUES(?,?,?)', (block_id, index, data))
                        elif table == 'LadderBlocks':
                            db.execute('INSERT INTO LadderBlocks VALUES(?,?,?,?)', (block_id, index, 0, 'synthetic carrier'))
                        else:
                            db.execute('INSERT INTO T_Block VALUES(?,?)', (index, block_id))
                            for width in widths:
                                db.execute('INSERT INTO T_Step VALUES(?,?,?,?)', (position, block_id, '', width))
                                position += 1
                    db.commit()
                    entries[entry] = db.serialize()
                finally:
                    db.close()
            with zipfile.ZipFile(source, 'w') as archive:
                for name, body in entries.items():
                    archive.writestr(name, body)
            before = source.read_bytes()
            output = root / 'ir'
            result = subprocess.run([sys.executable, '-I', '-B', '-m', 'gx3_fx5_parser_toolkit.cli', str(source),
                                     '--phase2-output', str(output)], cwd=root, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            ir = json.loads((output / 'neutral-ir.json').read_bytes())
            rows = ir['pous'][0]['records']
            self.assertEqual(ir['coverage']['record'], dict(total=12, decoded=12, partial=0, unknown=0))
            self.assertEqual([r['step'] for r in rows], [0, 2, 5, 7, 7, 11, 12, 14, 16, 16, 20, 21])
            self.assertEqual([r['opcode'] for r in rows], ['LD', 'CALL', 'LD', 'MOV', None, 'FEND', 'P255', 'LD', 'MOV', None, 'RET', 'END'])
            for index in (4, 9):
                self.assertEqual(rows[index]['kind'], 'continuation')
                self.assertEqual(rows[index]['continues_record_id'], rows[index - 1]['record_id'])
            self.assertEqual(rows[1]['operands'][0]['raw_token'], 'P255')
            self.assertEqual(source.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
