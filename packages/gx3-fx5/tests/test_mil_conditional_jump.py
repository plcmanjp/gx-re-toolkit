"""Synthetic CJ serialization coverage, not CPU or control-flow acceptance."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from gx3_fx5_profile.decoder import MiningRequired, _decode_mil
from test_installed_semantics import synthetic_gx3
from test_mil_pointer_control import combined, contact, mov, pointer_control, terminator


class ConditionalJumpMilTests(unittest.TestCase):
    def test_cj_retains_distinct_mnemonic_and_pointer_ordinal(self):
        for ordinal in (0, 255, 256, 4095):
            with self.subTest(ordinal=ordinal):
                self.assertEqual(_decode_mil(pointer_control('CJ', ordinal), 1), [
                    dict(kind='instruction', opcode='CJ', operands=[f'P{ordinal}'], text=None)])

    def test_contact_and_jump_share_a_block_without_losing_order(self):
        data = combined(contact('M', 9), pointer_control('CJ', 256))
        self.assertEqual(_decode_mil(data, 2), [
            dict(kind='instruction', opcode='LD', operands=['M9'], text=None),
            dict(kind='instruction', opcode='CJ', operands=['P256'], text=None)])
        for count in (1, 3):
            with self.subTest(count=count), self.assertRaises(MiningRequired):
                _decode_mil(data, count)

    def test_nearby_jump_shapes_remain_unmined(self):
        data = pointer_control('CJ')
        for old, new in (('CJ:P:', 'CJP:P:'), ('CJ:P:', 'CJ:I:'),
                         ('cl{op=#:ct=a:', 'm{op=#:'),
                         ('ct=a:as=', 'ct=a:extra=1:as='),
                         ('a=255:vt=nn', 'a=255:vt=nn:extra=1'),
                         ('vt=p', 'vt=A16'), ('ct=a', 'ct=p')):
            with self.subTest(new=new), self.assertRaises(MiningRequired):
                _decode_mil(data.replace(old, new), 1)


class InstalledConditionalJumpTests(unittest.TestCase):
    def test_installed_full_program_steps_coverage_and_input_preservation(self):
        for ordinal in (255, 256):
            with self.subTest(ordinal=ordinal), tempfile.TemporaryDirectory(prefix='gx-cj-') as directory:
                root = Path(directory)
                source = root / 'synthetic-cj.gx3'
                synthetic_gx3(source, mil_mov=True)
                with zipfile.ZipFile(source) as archive:
                    entries = {name: archive.read(name) for name in archive.namelist()}
                blocks = [(combined(contact(), pointer_control('CJ', ordinal)), [2, 3]),
                          (combined(contact('SM', 400), mov()), [2, 4]),
                          (combined(pointer_control('Pointer', ordinal), contact('SM', 400), mov(6, 11)), [2, 2, 4]),
                          (terminator('END'), [1])]
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
                            block = f'block-{index}'
                            if table == 'MIL':
                                db.execute('INSERT INTO MIL VALUES(?,?,?)', (block, index, data))
                            elif table == 'LadderBlocks':
                                db.execute('INSERT INTO LadderBlocks VALUES(?,?,?,?)', (block, index, 0, 'synthetic carrier'))
                            else:
                                db.execute('INSERT INTO T_Block VALUES(?,?)', (index, block))
                                for width in widths:
                                    db.execute('INSERT INTO T_Step VALUES(?,?,?,?)', (position, block, '', width))
                                    position += 1
                        db.commit()
                        entries[entry] = db.serialize()
                    finally:
                        db.close()
                with zipfile.ZipFile(source, 'w') as archive:
                    for name, body in entries.items():
                        archive.writestr(name, body)
                before = source.read_bytes()
                result = subprocess.run([sys.executable, '-I', '-B', '-m', 'gx3_fx5_parser_toolkit.cli',
                                         str(source), '--phase2-output', str(root / 'ir')],
                                        cwd=root, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((root / 'ir/neutral-ir.json').read_bytes())
                rows = ir['pous'][0]['records']
                self.assertEqual(ir['coverage']['record'], dict(total=10, decoded=10, partial=0, unknown=0))
                self.assertEqual([r['step'] for r in rows], [0, 2, 5, 7, 7, 11, 13, 15, 15, 19])
                self.assertEqual([r['opcode'] for r in rows], ['LD', 'CJ', 'LD', 'MOV', None, f'P{ordinal}', 'LD', 'MOV', None, 'END'])
                self.assertEqual(rows[1]['operands'][0]['raw_token'], f'P{ordinal}')
                for index in (4, 8):
                    self.assertEqual(rows[index]['continues_record_id'], rows[index - 1]['record_id'])
                self.assertEqual(source.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
