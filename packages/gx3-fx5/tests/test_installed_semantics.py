"""Independent synthetic GX3 carriers exercised through the installed CLI."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from gx3_fx5_profile.decoder import MiningRequired, _decode_mil, _format_operand


def database(path: Path, statements: tuple[str, ...]) -> bytes:
    connection = sqlite3.connect(path)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    return path.read_bytes()


MOV_MIL = (
    "V1:1:1:1:MOV:D:D:ms{el=[mc{op=cl{op=0:ct=a:as=[as{vt=A16}:as{vt=A16}]}:"
    "as=[d{s=0:a=5:vt=nn}:d{s=0:a=10:vt=nn}]}]}"
)


def synthetic_gx3(path: Path, *, unknown: bool = False, missing_step: bool = False, mil_mov: bool = False) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ladder_rows = (
            "INSERT INTO LadderBlocks VALUES('block-a',0,0,'synthetic carrier')",
        ) if mil_mov else (
            "INSERT INTO LadderBlocks VALUES('block-a',0,3,'V1:0:nop{nop=fnn{n=1}:dim=1x1}')",
            "INSERT INTO LadderBlocks VALUES('block-b',1,5,'V1:0:end{type=end:dim=1x1}')" if not unknown else
            "INSERT INTO LadderBlocks VALUES('block-b',1,5,'V1:0:unknown')",
        )
        ladder = database(root / "ladder.db", (
            "CREATE TABLE LadderBlocks(id TEXT,pos REAL,blocktype INTEGER,data TEXT)", *ladder_rows,
        ))
        mil_rows = ("INSERT INTO MIL VALUES('block-a',0,'" + MOV_MIL + "')",) if mil_mov else ()
        mil = database(root / "mil.db", ("CREATE TABLE MIL(id TEXT,pos REAL,data TEXT)", *mil_rows))
        step_rows = () if mil_mov else (
            "INSERT INTO T_Block VALUES(1,'block-b')",
            "INSERT INTO T_Step VALUES(1,'block-b','',1)",
        )
        step = database(root / "step.db", (
            "CREATE TABLE T_Block(Pos REAL,BlockID TEXT)",
            "CREATE TABLE T_Step(Pos INTEGER,BlockID TEXT,MilID TEXT,StepSize INTEGER)",
            "INSERT INTO T_Block VALUES(0,'block-a')",
            "INSERT INTO T_Step VALUES(0,'block-a','',1)",
            *step_rows,
        ))
        name = "MAIN".encode("utf-16le") + b"\x00\x00"
        entries = {
            "Config.xml": b'<Config Unit="FX5U" UnitId="528" Title="Synthetic"/>',
            "ConvertData/1/PouLinkOrder.info": b"1\n",
            "ConvertData/1/Program.qpg": len(name).to_bytes(2, "little") + name,
            "ConvertData/1/PouPCode.pcode": b"synthetic",
            "SYN_LDDB.db": ladder,
            "SYN_MilDB.db": mil,
        }
        if not missing_step:
            entries["1_StepInfo.db"] = step
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, body in entries.items():
                archive.writestr(name, body)


class InstalledSemanticsTests(unittest.TestCase):
    def test_mil_operand_order_radix_width_and_unknown_signature(self) -> None:
        source = MOV_MIL
        self.assertEqual(_decode_mil(source, 1), [
            {"kind": "instruction", "opcode": "MOV", "operands": ["D5", "D10"], "text": None}
        ])
        self.assertEqual(_format_operand(["X"], ("scalar", (0x421,))), ("X421", 1))
        self.assertEqual(_format_operand(["B"], ("scalar", (0x2A,))), ("B2A", 1))
        self.assertEqual(_format_operand(["Us", "G", "Dots"], ("remote_bit", (1, 10, 15))), ("U1\\G10.F", 3))
        with self.assertRaises(MiningRequired):
            _decode_mil(source.replace("MOV:D:D", "UNKNOWN:D:D"), 1)

    def test_full_cli_preserves_nop_end_unknown_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "synthetic.gx3"
            synthetic_gx3(source)
            before = source.read_bytes()
            output = root / "output"
            result = subprocess.run(
                [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source), "--phase2-output", str(output)],
                cwd=root, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(ir["profile"]["detector_status"], "SUPPORTED")
            self.assertEqual(ir["pous"][0]["name"], "MAIN")
            self.assertEqual([item["opcode"] for item in ir["pous"][0]["records"]], ["NOP", "END"])
            self.assertEqual(ir["coverage"]["record"], {"total": 2, "decoded": 2, "partial": 0, "unknown": 0})
            self.assertEqual(source.read_bytes(), before)

            unknown = root / "unknown.gx3"
            synthetic_gx3(unknown, unknown=True)
            output2 = root / "unknown-output"
            result = subprocess.run(
                [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(unknown), "--phase2-output", str(output2)],
                cwd=root, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            ir = json.loads((output2 / "neutral-ir.json").read_text(encoding="utf-8"))
            self.assertEqual([item["status"] for item in ir["pous"][0]["records"]], ["decoded", "unknown"])
            self.assertEqual(ir["coverage"]["record"], {"total": 2, "decoded": 1, "partial": 0, "unknown": 1})
            self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED" for item in ir["pous"][0]["findings"]))

    def test_missing_relation_does_not_guess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "missing.gx3"
            synthetic_gx3(source, missing_step=True)
            output = Path(directory) / "output"
            result = subprocess.run(
                [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source), "--phase2-output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(ir["profile"]["detector_status"], "AMBIGUOUS")
            self.assertEqual(ir["pous"], [])

    def test_full_cli_mil_operand_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "mov.gx3"
            synthetic_gx3(source, mil_mov=True)
            output = Path(directory) / "mov-output"
            result = subprocess.run(
                [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source), "--phase2-output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
            records = ir["pous"][0]["records"]
            self.assertEqual([(item["kind"], item["opcode"], item["operands"][0]["raw_token"])
                              for item in records], [("instruction", "MOV", "D5"), ("continuation", None, "D10")])
            self.assertEqual(records[1]["continues_record_id"], records[0]["record_id"])
            self.assertEqual(ir["coverage"]["record"], {"total": 2, "decoded": 2, "partial": 0, "unknown": 0})


if __name__ == "__main__":
    unittest.main()
