"""Independent synthetic GX3 carriers exercised through the installed CLI."""

from __future__ import annotations

import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from gx3_fx5_profile.decoder import MiningRequired, _decode_lddb, _decode_mil, _format_operand, _operand


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

F_OUT_MIL = (
    "V1:1:1:1:OUT:F:ms{el=[mc{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:"
    "as=[d{s=#:a=64:vt=nn}]}]}"
)

C_CONTACT_MIL = (
    "V1:1:1:A:C:ms{el=[mc{op=lct{op=#:lt=l:ct=a:as=[as{vt=Abl}]}:"
    "as=[d{s=#:a=5:vt=nn}]}]}"
)
C_OUT_MIL = (
    "V1:1:1:1:OUT:C:K_1:ms{el=[mc{op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=A16}]}:"
    "as=[d{s=#:a=5:vt=nn}:c{s=#:v=3:si=s}]}]}"
)
C_RESET_MIL = (
    "V1:1:1:RST:C:ms{el=[mc{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:"
    "as=[d{s=#:a=5:vt=nn}]}]}"
)
LC_CONTACT_MIL = C_CONTACT_MIL.replace("A:C:", "A:LC:")
LC_OUT_MIL = C_OUT_MIL.replace("OUT:C:K_1:", "OUT:LC:K_2:").replace("A16", "A32")
LC_RESET_MIL = C_RESET_MIL.replace("RST:C:", "RST:LC:")

C_OUT_LDDB = (
    "V1:5:1:1:7:1:3:a:M:OUT__16:C:K_1:cb{fg=fg{dim=4x1:es=["
    "e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=7:vt=nn}]}:pos=0,0}:"
    "e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=A16}]}:"
    "args=[d{s=#:a=5:vt=nn}:c{s=#:v=3:si=s}]}:pos=1,0}]}}"
)
C_CONTACT_LDDB = (
    "V1:4:1:1:1:1:a:C:c:M:cb{fg=fg{dim=2x1:es=["
    "e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=5:vt=nn}]}:pos=0,0}:"
    "e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=10:vt=nn}]}:pos=1,0}]}}"
)
C_RESET_LDDB = (
    "V1:4:1:1:3:1:a:M:RST:C:cb{fg=fg{dim=3x1:es=["
    "e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=7:vt=nn}]}:pos=0,0}:"
    "e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=5:vt=nn}]}:pos=1,0}]}}"
)
LC_OUT_LDDB = C_OUT_LDDB.replace("OUT__16:C:K_1:", "OUT__32:LC:K_2:").replace("A16", "A32")
LC_CONTACT_LDDB = C_CONTACT_LDDB.replace("a:C:", "a:LC:")
LC_RESET_LDDB = C_RESET_LDDB.replace("RST:C:", "RST:LC:")

SB_CONTACT_MIL = C_CONTACT_MIL.replace("A:C:", "A:SB:")
SB_OUT_MIL = F_OUT_MIL.replace("OUT:F:", "OUT:SB:").replace("a=64:", "a=5:")
SB_CONTACT_LDDB = C_CONTACT_LDDB.replace("a:C:", "a:SB:")
SB_OUT_LDDB = C_CONTACT_LDDB.replace("a:C:c:M:", "a:M:c:SB:").replace("a=10:", "a=5:")

SW_MOV_MIL = MOV_MIL.replace("MOV:D:D:", "MOV:D:SW:").replace("op=0", "op=#").replace("s=0", "s=#")
SW_MOV_LDDB = (
    "V1:4:1:1:1:1:a:M:MOV:D:SW:cb{fg=fg{dim=2x1:es=["
    "e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=7:vt=nn}]}:pos=0,0}:"
    "e{s=ce{op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}:"
    "args=[d{s=#:a=5:vt=nn}:d{s=#:a=10:vt=nn}]}:pos=1,0}]}}"
)

C_READ_MIL = MOV_MIL.replace("MOV:D:D:", "MOV:C:D:").replace("op=0", "op=#").replace("s=0", "s=#")
C_READ_MIL = C_READ_MIL.replace("a=5:", "a=127:").replace("a=10:", "a=22:")
C_READ_LDDB = SW_MOV_LDDB.replace("MOV:D:SW:", "MOV:C:D:").replace("a=5:", "a=127:").replace("a=10:", "a=22:")
LC_READ_MIL = C_READ_MIL.replace("MOV:C:D:", "MOV:LC:D:").replace("A16", "A32").replace("a=127:", "a=31:")
LC_READ_LDDB = C_READ_LDDB.replace("MOV:C:D:", "DMOV:LC:D:").replace("A16", "A32").replace("a=127:", "a=31:")

E_EMOV_LDDB = (
    "V1:4:1:1:1:1:a:M:EMOV:E_2n:D:cb{fg=fg{dim=2x1:es=["
    "e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=7:vt=nn}]}:pos=0,0}:"
    "e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}:"
    "args=[c{s=#:v=3F9D70A4}:d{s=#:a=22:vt=nn}]}:pos=1,0}]}}"
)

E_EMOV_MIL = (
    "V1:1:1:1:MOV:E_2n:D:ms{el=["
    "mc{op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}:"
    "as=[c{s=#:v=3F9D70A4}:d{s=#:a=22:vt=nn}]}]}"
)

S_OUT_LDDB = (
    "V1:4:1:1:1:4:a:M:c:SfcS:cb{fg=fg{dim=2x1:es=["
    "e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=901:vt=nn}]}:pos=0,0}"
    "e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=1:vt=nn}]}:pos=1,0}"
    "]}}"
)


def synthetic_gx3(path: Path, *, unknown: bool = False, missing_step: bool = False,
                  mil_mov: bool = False, mil_source: str = MOV_MIL,
                  lddb_source: str | None = None) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ladder_rows = (
            "INSERT INTO LadderBlocks VALUES('block-a',0,0,'synthetic carrier')",
        ) if mil_mov else (
            "INSERT INTO LadderBlocks VALUES('block-a',0,3,'V1:0:nop{nop=fnn{n=1}:dim=1x1}')",
            "INSERT INTO LadderBlocks VALUES('block-b',1,5,'V1:0:end{type=end:dim=1x1}')" if not unknown else
            "INSERT INTO LadderBlocks VALUES('block-b',1,5,'V1:0:unknown')",
        )
        if lddb_source is not None:
            ladder_rows = (
                "INSERT INTO LadderBlocks VALUES('block-a',0,0,'" + lddb_source + "')",
                "INSERT INTO LadderBlocks VALUES('block-b',1,5,'V1:0:end{type=end:dim=1x1}')",
            )
        ladder = database(root / "ladder.db", (
            "CREATE TABLE LadderBlocks(id TEXT,pos REAL,blocktype INTEGER,data TEXT)", *ladder_rows,
        ))
        mil_rows = ("INSERT INTO MIL VALUES('block-a',0,'" + mil_source + "')",) if mil_mov else ()
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
            *(("INSERT INTO T_Step VALUES(1,'block-a','',1)",) if lddb_source is not None else ()),
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
    def test_emov_mil_float32_exact_context_roundtrip(self) -> None:
        for bits, token in (("3F9D70A4", "E1.23"), ("BF9D70A4", "E-1.23"),
                            ("41200000", "E10"), ("3F000000", "E0.5"), ("00000000", "E0")):
            with self.subTest(bits=bits):
                self.assertEqual(_decode_mil(E_EMOV_MIL.replace("3F9D70A4", bits), 1), [
                    {"kind": "instruction", "opcode": "EMOV", "operands": [token, "D22"], "text": None}
                ])
                self.assertEqual(struct.pack(">f", float(token[1:])).hex().upper(), bits)

    def test_emov_mil_float32_near_matches_remain_unmined(self) -> None:
        mutations = [E_EMOV_MIL.replace("3F9D70A4", bits) for bits in (
            "7F800000", "FF800000", "7FC00000", "00000001", "80000000", "3F800001",
            "3F9D70A", "03F9D70A4", "3f9d70a4", "3F9D70AG", "1.23",
        )]
        mutations.extend(E_EMOV_MIL.replace(a, b) for a, b in (
            ("MOV:E_2n:D:", "MOV:D:E_2n:"), ("MOV:", "DEMOV:"), ("MOV:", "EMOV:"),
            ("E_2n:", "E:"), ("E_2n:D:", "E_2n:E_2n:"), ("Ar32", "A32"),
            ("Ar32", "Ar64"), ("ct=a", "ct=p"), ("op=#", "op=0"),
            ("v=3F9D70A4}", "v=3F9D70A4:si=u}"), ("a=22:", "a=-1:"),
            ("s=#:a=22", "s=0:a=22"), ("vt=Ar32}", "vt=Ar32:extra=1}"),
            ("ct=a:as=", "ct=a:extra=1:as="),
        ))
        for raw in mutations:
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_mil(raw, 1)
        with self.assertRaises(MiningRequired):
            _decode_mil(E_EMOV_MIL, 2)
        with self.assertRaises(MiningRequired):
            _format_operand(["E_2n"], ("scalar", (1,)))

    def test_emov_mil_mixed_logic_complete_record_sequence(self) -> None:
        raw = E_EMOV_MIL.replace("MOV:E_2n:D:", "A:M:MOV:E_2n:D:").replace(
            "ms{el=[", "ms{el=[mc{op=lct{op=#:lt=l:ct=a:as=[as{vt=Abl}]}:as=[d{s=#:a=7:vt=nn}]}:")
        self.assertEqual(_decode_mil(raw, 2), [
            {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None},
            {"kind": "instruction", "opcode": "EMOV", "operands": ["E1.23", "D22"], "text": None},
        ])

    def test_installed_cli_emov_mil_coverage_and_preservation(self) -> None:
        for bits, token in (("3F9D70A4", "E1.23"), ("BF9D70A4", "E-1.23"),
                            ("00000000", "E0"), ("7FC00000", None)):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "synthetic-emov-mil.gx3"
                synthetic_gx3(source, mil_mov=True,
                              mil_source=E_EMOV_MIL.replace("3F9D70A4", bits))
                before = source.read_bytes()
                output = root / "output"
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                     "--phase2-output", str(output)],
                    cwd=root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                records = ir["pous"][0]["records"]
                if token is not None:
                    self.assertEqual([
                        (record["kind"], record["opcode"], [operand["raw_token"] for operand in record["operands"]])
                        for record in records
                    ], [("instruction", "EMOV", [token]), ("continuation", None, ["D22"])])
                    self.assertEqual([record["status"] for record in records], ["decoded"] * 2)
                    self.assertEqual(records[1]["continues_record_id"], records[0]["record_id"])
                    self.assertEqual(ir["coverage"]["record"], {"total": 2, "decoded": 2, "partial": 0, "unknown": 0})
                else:
                    self.assertEqual([record["status"] for record in records], ["unknown"])
                    self.assertEqual(ir["coverage"]["record"], {"total": 1, "decoded": 0, "partial": 0, "unknown": 1})
                    self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED" for item in ir["pous"][0]["findings"]))
                self.assertEqual(source.read_bytes(), before)

    def test_emov_lddb_float32_plain_decimal_roundtrip(self) -> None:
        for bits, token in (
            ("3F9D70A4", "E1.23"), ("BF9D70A4", "E-1.23"),
            ("3F000000", "E0.5"), ("3FC00000", "E1.5"), ("00000000", "E0"),
        ):
            with self.subTest(bits=bits):
                raw = E_EMOV_LDDB.replace("3F9D70A4", bits)
                self.assertEqual(_decode_lddb(raw, 0, 2), [
                    {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None},
                    {"kind": "instruction", "opcode": "EMOV", "operands": [token, "D22"], "text": None},
                ])
                self.assertEqual(struct.pack(">f", float(token[1:])).hex().upper(), bits)

    def test_emov_lddb_float32_near_matches_remain_unmined(self) -> None:
        for bits in (
            "7F800000", "FF800000", "7FC00000", "FFFFFFFF",  # Inf/NaN.
            "00000001", "007FFFFF", "80000000",  # Subnormal or negative zero.
            "3F800001", "2EDBE6FF",  # Needs more than seven digits or scientific notation.
            "3F9D70A", "03F9D70A4", "3f9d70a4", "3F9D70AG", "-3F9D70A4", "1.23",
        ):
            with self.subTest(bits=bits), self.assertRaises(MiningRequired):
                _decode_lddb(E_EMOV_LDDB.replace("3F9D70A4", bits), 0, 2)
        for raw in (
            E_EMOV_LDDB.replace("EMOV:E_2n:D:", "EMOV:D:E_2n:"),
            E_EMOV_LDDB.replace("EMOV:E_2n:D:", "EMOV:E_2n:E_2n:"),
            E_EMOV_LDDB.replace("E_2n:", "E:"),
            E_EMOV_LDDB.replace("E_2n:", "E_2n:E_2n:"),
            E_EMOV_LDDB.replace("EMOV:", "MOV:"),
            E_EMOV_LDDB.replace("EMOV:", "DEMOV:"),
            E_EMOV_LDDB.replace("Ar32", "A32"),
            E_EMOV_LDDB.replace("Ar32", "Ar64"),
            E_EMOV_LDDB.replace("ct=a", "ct=p"),
            E_EMOV_LDDB.replace("op=#", "op=0"),
            E_EMOV_LDDB.replace("a=22:", "a=-1:"),
            E_EMOV_LDDB.replace("s=#:a=22", "s=0:a=22"),
            E_EMOV_LDDB.replace("c{s=#:v=3F9D70A4}", "c{s=#:v=3F9D70A4:si=u}"),
            E_EMOV_LDDB.replace("c{s=#:v=3F9D70A4}", "M{b=c{s=#:v=3F9D70A4}:m=d{s=#:a=1:vt=nn}}")
                .replace("E_2n:D:", "E_2n:Zs:D:"),
            E_EMOV_LDDB.replace("d{s=#:a=22:vt=nn}", "M{b=d{s=#:a=22:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                .replace("E_2n:D:", "E_2n:D:Zs:"),
            E_EMOV_LDDB.replace("d{s=#:a=22:vt=nn}", "M{b=d{s=#:a=22:vt=nn}:m=c{s=#:v=2}}")
                .replace("E_2n:D:", "E_2n:D:Ks:"),
            E_EMOV_LDDB.replace("EMOV:E_2n:", "Zs:EMOV:E_2n:"),
            E_EMOV_LDDB.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
            E_EMOV_LDDB.replace("e{s=ce{", "e{s=ce{unknown=1:"),
            E_EMOV_LDDB.replace("vt=Ar32}", "vt=Ar32:unknown=1}"),
            E_EMOV_LDDB.replace("}:pos=", "}:unknown=1:pos="),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)
        with self.assertRaises(MiningRequired):
            _format_operand(["E_2n"], ("scalar", (1,)))

    def test_installed_cli_emov_lddb_continuation_coverage_and_preservation(self) -> None:
        for bits, token, expected in (
            ("3F9D70A4", "E1.23", "decoded"),
            ("BF9D70A4", "E-1.23", "decoded"),
            ("00000000", "E0", "decoded"),
            ("7FC00000", None, "unknown"),
        ):
            raw = E_EMOV_LDDB.replace("3F9D70A4", bits)
            with self.subTest(bits=bits, expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "synthetic-emov.gx3"
                synthetic_gx3(source, lddb_source=raw)
                before = source.read_bytes()
                output = root / "output"
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                     "--phase2-output", str(output)],
                    cwd=root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                records = ir["pous"][0]["records"]
                if expected == "decoded":
                    self.assertEqual([
                        (record["kind"], record["opcode"], [operand["raw_token"] for operand in record["operands"]])
                        for record in records
                    ], [("instruction", "LD", ["M7"]), ("instruction", "EMOV", [token]),
                        ("continuation", None, ["D22"]), ("instruction", "END", [])])
                    self.assertEqual([
                        (operand["kind"], operand["value"], operand["raw_token"])
                        for record in records for operand in record["operands"]
                    ], [("device", "M7", "M7"), ("constant", token, token), ("device", "D22", "D22")])
                    self.assertEqual([record["status"] for record in records], ["decoded"] * 4)
                    self.assertEqual([record["continues_record_id"] for record in records],
                                     [None, None, records[1]["record_id"], None])
                    self.assertEqual(ir["coverage"]["record"], {"total": 4, "decoded": 4, "partial": 0, "unknown": 0})
                else:
                    self.assertEqual([record["status"] for record in records], ["unknown", "unknown", "decoded"])
                    self.assertEqual(ir["coverage"]["record"], {"total": 3, "decoded": 1, "partial": 0, "unknown": 2})
                    self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED" for item in ir["pous"][0]["findings"]))
                self.assertEqual(source.read_bytes(), before)

    def test_e_constant_classification_requires_canonical_plain_decimal(self) -> None:
        for token in ("E1.23", "E-1.23", "E0", "E0.5"):
            with self.subTest(token=token):
                operand = _operand(token, 0, {}, {}, set(), None)
                self.assertEqual((operand["kind"], operand["value"], operand["raw_token"]),
                                 ("constant", token, token))
        for token in (
            "ER1.23", "ED1.23", "E_2n", "E", "E1e3", "E+1.23", "E01.23",
            "E1.", "E.5", "E-0", "E0.0", "E1.230", "E1.23\\D22", "E1.23Z1",
        ):
            with self.subTest(token=token):
                operand = _operand(token, 0, {}, {}, set(), None)
                self.assertEqual((operand["kind"], operand["value"], operand["raw_token"]),
                                 ("device", token, token))

    def test_s_lddb_coil_uses_canonical_decimal_addresses(self) -> None:
        for address in (0, 1, 255, 256, 4095):
            with self.subTest(address=address):
                source = S_OUT_LDDB.replace("a=1:", f"a={address}:")
                self.assertEqual(_decode_lddb(source, 0, 2), [
                    {"kind": "instruction", "opcode": "LD", "operands": ["M901"], "text": None},
                    {"kind": "instruction", "opcode": "OUT", "operands": [f"S{address}"], "text": None},
                ])

    def test_s_lddb_unmined_shapes_and_descriptors_stay_closed(self) -> None:
        for source in (
            S_OUT_LDDB.replace("SfcS:", "UNMINED:"),
            S_OUT_LDDB.replace("SfcS:", "SfcS:UNMINED:"),
            S_OUT_LDDB.replace("a=1:vt=nn", "a=1:vt=UNMINED"),
            S_OUT_LDDB.replace("d{s=#:a=1:vt=nn}", "M{b=d{s=#:a=1:vt=nn}:m=c{s=#:v=2}}"),
            S_OUT_LDDB.replace("pos=1,0", "pos=2,0"),
        ):
            with self.subTest(source=source), self.assertRaises(MiningRequired):
                _decode_lddb(source, 0, 2)

    def test_installed_cli_s_lddb_preserves_input_and_unknown_records(self) -> None:
        for source_text, expected in (
            (S_OUT_LDDB, "decoded"),
            (S_OUT_LDDB.replace("a=1:vt=nn", "a=1:vt=UNMINED"), "unknown"),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "synthetic-s.gx3"
                synthetic_gx3(source, lddb_source=source_text)
                before = source.read_bytes()
                output = root / "output"
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                     "--phase2-output", str(output)],
                    cwd=root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                records = ir["pous"][0]["records"]
                self.assertEqual([record["status"] for record in records], [expected, expected, "decoded"])
                if expected == "decoded":
                    self.assertEqual(records[1]["opcode"], "OUT")
                    self.assertEqual(records[1]["operands"][0]["raw_token"], "S1")
                else:
                    self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED"
                                        for item in ir["pous"][0]["findings"]))
                self.assertEqual(ir["coverage"]["record"], {
                    "total": 3, "decoded": 3 if expected == "decoded" else 1,
                    "partial": 0, "unknown": 0 if expected == "decoded" else 2,
                })
                self.assertEqual(source.read_bytes(), before)

    def test_f_out_scalar_decimal_boundary_addresses(self) -> None:
        for address in (0, 63, 64, 127):
            with self.subTest(address=address):
                self.assertEqual(_decode_mil(F_OUT_MIL.replace("a=64:", f"a={address}:"), 1), [
                    {"kind": "instruction", "opcode": "OUT", "operands": [f"F{address}"], "text": None}
                ])

    def test_sb_scalar_ld_out_hex_boundary_addresses(self) -> None:
        # Canonical hexadecimal spelling omits optional leading zeroes.
        for address, token in ((0, "SB0"), (5, "SB5"), (255, "SBFF"), (256, "SB100")):
            for mil, opcode in ((SB_CONTACT_MIL, "LD"), (SB_OUT_MIL, "OUT")):
                with self.subTest(route="MIL", address=address, opcode=opcode):
                    self.assertEqual(_decode_mil(mil.replace("a=5:", f"a={address}:"), 1), [
                        {"kind": "instruction", "opcode": opcode, "operands": [token], "text": None}
                    ])
            for fixture, operands in (
                (SB_CONTACT_LDDB, [[token], ["M10"]]),
                (SB_OUT_LDDB, [[f"M{address}"], [token]]),
            ):
                with self.subTest(route="LDDB", address=address, fixture=fixture):
                    rows = _decode_lddb(fixture.replace("a=5:", f"a={address}:"), 0, 2)
                    self.assertEqual([row["opcode"] for row in rows], ["LD", "OUT"])
                    self.assertEqual([row["operands"] for row in rows], operands)

    def test_lddb_string_literal_sb_is_not_a_device_tag(self) -> None:
        raw = (
            'V1:4:1:1:1:1:a:M:$MOV:String:SB:"SB":D:cb{fg=fg{dim=2x1:es=['
            'e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a=7:vt=nn}]}:pos=0,0}:'
            'e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}:'
            'args=[c{s=#:v=#:t=#}:d{s=#:a=10:vt=nn}]}:pos=1,0}]}}'
        )
        self.assertEqual(_decode_lddb(raw, 0, 2), [
            {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None},
            {"kind": "instruction", "opcode": "$MOV", "operands": ['"SB"', "D10"], "text": None},
        ])
        self.assertEqual(_decode_lddb(raw.replace('String:SB:"SB":', 'String:SW:"SW":'), 0, 2), [
            {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None},
            {"kind": "instruction", "opcode": "$MOV", "operands": ['"SW"', "D10"], "text": None},
        ])

    def test_sw_scalar_mov_both_directions_hex_boundary_addresses(self) -> None:
        for address, token in ((0, "SW0"), (255, "SWFF"), (256, "SW100")):
            for reverse in (False, True):
                operand_address = 5 if reverse else 10
                operands = [token, "D10"] if reverse else ["D5", token]
                for route, fixture in (("MIL", SW_MOV_MIL), ("LDDB", SW_MOV_LDDB)):
                    raw = fixture.replace("MOV:D:SW:", "MOV:SW:D:") if reverse else fixture
                    raw = raw.replace(f"a={operand_address}:", f"a={address}:")
                    with self.subTest(route=route, address=address, reverse=reverse):
                        rows = _decode_mil(raw, 1) if route == "MIL" else _decode_lddb(raw, 0, 2)
                        expected = [{"kind": "instruction", "opcode": "MOV", "operands": operands, "text": None}]
                        if route == "LDDB":
                            expected.insert(0, {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None})
                        self.assertEqual(rows, expected)

    def test_counter_current_read_mov_scalar_boundaries(self) -> None:
        for address in (127, 128):
            for route, fixture in (("MIL", C_READ_MIL), ("LDDB", C_READ_LDDB)):
                with self.subTest(route=route, address=address):
                    raw = fixture.replace("a=127:", f"a={address}:")
                    rows = _decode_mil(raw, 1) if route == "MIL" else _decode_lddb(raw, 0, 2)
                    expected = [{"kind": "instruction", "opcode": "MOV", "operands": [f"C{address}", "D22"], "text": None}]
                    if route == "LDDB":
                        expected.insert(0, {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None})
                    self.assertEqual(rows, expected)

    def test_counter_current_read_mov_near_matches_remain_unmined(self) -> None:
        for route, fixture in (("MIL", C_READ_MIL), ("LDDB", C_READ_LDDB)):
            for raw in (
                fixture.replace("MOV:C:D:", "MOV:D:C:"),
                fixture.replace("MOV:C:D:", "MOV:C:C:"),
                fixture.replace("MOV:C:D:", "MOV:LC:D:"),
                fixture.replace("MOV:C:D:", "DMOV:C:D:"),
                fixture.replace("A16", "A32"),
                fixture.replace("A16", "A16s"),
                fixture.replace("ct=a", "ct=p"),
                fixture.replace("op=#", "op=0"),
                fixture.replace("a=127:", "a=-1:"),
                fixture.replace("a=22:", "a=-1:"),
                fixture.replace("s=#:a=127", "s=0:a=127"),
                fixture.replace("vt=nn", "vt=UNMINED"),
                fixture.replace("MOV:C:D:", "MOV:C:C:D:"),
                fixture.replace("d{s=#:a=127:vt=nn}", "M{b=d{s=#:a=127:vt=nn}:m=c{s=#:v=2}}")
                    .replace("MOV:C:D:", "MOV:C:Ks:D:"),
                fixture.replace("d{s=#:a=127:vt=nn}", "M{b=d{s=#:a=127:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                    .replace("MOV:C:D:", "MOV:C:Zs:D:"),
                fixture.replace("d{s=#:a=22:vt=nn}", "M{b=d{s=#:a=22:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                    .replace("MOV:C:D:", "MOV:C:D:Zs:"),
                fixture.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
                fixture.replace("vt=A16}", "vt=A16:unknown=1}"),
            ):
                with self.subTest(route=route, raw=raw), self.assertRaises(MiningRequired):
                    if route == "MIL":
                        _decode_mil(raw, 1)
                    else:
                        _decode_lddb(raw, 0, 2)
        for raw in (
            C_READ_LDDB.replace("MOV:C:D:", "Zs:MOV:C:D:"),
            C_READ_LDDB.replace("e{s=ce{", "e{s=ce{unknown=1:"),
            C_READ_LDDB.replace("}:pos=", "}:unknown=1:pos="),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)

    def test_long_counter_current_read_dmov_scalar_boundaries(self) -> None:
        for address in (31, 32):
            for route, fixture in (("MIL", LC_READ_MIL), ("LDDB", LC_READ_LDDB)):
                with self.subTest(route=route, address=address):
                    raw = fixture.replace("a=31:", f"a={address}:")
                    rows = _decode_mil(raw, 1) if route == "MIL" else _decode_lddb(raw, 0, 2)
                    expected = [{"kind": "instruction", "opcode": "DMOV", "operands": [f"LC{address}", "D22"], "text": None}]
                    if route == "LDDB":
                        expected.insert(0, {"kind": "instruction", "opcode": "LD", "operands": ["M7"], "text": None})
                    self.assertEqual(rows, expected)

    def test_long_counter_current_read_dmov_near_matches_remain_unmined(self) -> None:
        for route, fixture in (("MIL", LC_READ_MIL), ("LDDB", LC_READ_LDDB)):
            marker = "MOV" if route == "MIL" else "DMOV"
            for raw in (
                fixture.replace(f"{marker}:LC:D:", f"{marker}:D:LC:"),
                fixture.replace(f"{marker}:LC:D:", f"{marker}:LC:LC:"),
                fixture.replace(f"{marker}:LC:D:", f"{marker}:C:D:"),
                fixture.replace(f"{marker}:LC:D:", "DMOV:LC:D:" if route == "MIL" else "MOV:LC:D:"),
                fixture.replace("A32", "A16"),
                fixture.replace("A32", "A32s"),
                fixture.replace("ct=a", "ct=p"),
                fixture.replace("op=#", "op=0"),
                fixture.replace("a=31:", "a=-1:"),
                fixture.replace("a=22:", "a=-1:"),
                fixture.replace("s=#:a=31", "s=0:a=31"),
                fixture.replace("vt=nn", "vt=UNMINED"),
                fixture.replace(":LC:D:", ":LC:LC:D:"),
                fixture.replace("d{s=#:a=31:vt=nn}", "M{b=d{s=#:a=31:vt=nn}:m=c{s=#:v=2}}")
                    .replace(":LC:D:", ":LC:Ks:D:"),
                fixture.replace("d{s=#:a=31:vt=nn}", "M{b=d{s=#:a=31:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                    .replace(":LC:D:", ":LC:Zs:D:"),
                fixture.replace("d{s=#:a=22:vt=nn}", "M{b=d{s=#:a=22:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                    .replace(":LC:D:", ":LC:D:Zs:"),
                fixture.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
                fixture.replace("vt=A32}", "vt=A32:unknown=1}"),
            ):
                with self.subTest(route=route, raw=raw), self.assertRaises(MiningRequired):
                    if route == "MIL":
                        _decode_mil(raw, 1)
                    else:
                        _decode_lddb(raw, 0, 2)
        for raw in (
            LC_READ_LDDB.replace("DMOV:LC:D:", "Zs:DMOV:LC:D:"),
            LC_READ_LDDB.replace("e{s=ce{", "e{s=ce{unknown=1:"),
            LC_READ_LDDB.replace("}:pos=", "}:unknown=1:pos="),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)

    def test_installed_cli_counter_current_read_continuation_and_preservation(self) -> None:
        for address, tag, base_address, opcode, mil_fixture, lddb_fixture in (
            (127, "C", 127, "MOV", C_READ_MIL, C_READ_LDDB),
            (128, "C", 127, "MOV", C_READ_MIL, C_READ_LDDB),
            (31, "LC", 31, "DMOV", LC_READ_MIL, LC_READ_LDDB),
            (32, "LC", 31, "DMOV", LC_READ_MIL, LC_READ_LDDB),
        ):
            for route, fixture in (("MIL", mil_fixture), ("LDDB", lddb_fixture)):
                for expected in ("decoded", "unknown"):
                    raw = fixture.replace(f"a={base_address}:", f"a={address}:")
                    if expected == "unknown":
                        raw = raw.replace("A16", "A32") if tag == "C" else raw.replace("A32", "A16")
                    with self.subTest(route=route, tag=tag, address=address, expected=expected), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = root / "synthetic-counter-read.gx3"
                        if route == "MIL":
                            synthetic_gx3(source, mil_mov=True, mil_source=raw)
                        else:
                            synthetic_gx3(source, lddb_source=raw)
                        before = source.read_bytes()
                        output = root / "output"
                        result = subprocess.run(
                            [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                             "--phase2-output", str(output)],
                            cwd=root, capture_output=True, text=True, timeout=30,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                        records = ir["pous"][0]["records"]
                        if expected == "decoded":
                            expected_rows = [("instruction", opcode, [f"{tag}{address}"]), ("continuation", None, ["D22"])]
                            base_index = 0 if route == "MIL" else 1
                            if route == "LDDB":
                                expected_rows.insert(0, ("instruction", "LD", ["M7"]))
                                expected_rows.append(("instruction", "END", []))
                            self.assertEqual([
                                (record["kind"], record["opcode"], [operand["raw_token"] for operand in record["operands"]])
                                for record in records
                            ], expected_rows)
                            self.assertEqual([record["status"] for record in records], ["decoded"] * len(expected_rows))
                            self.assertEqual([record["continues_record_id"] for record in records],
                                             [None, records[0]["record_id"]] if route == "MIL"
                                             else [None, None, records[base_index]["record_id"], None])
                            self.assertEqual(ir["coverage"]["record"], {
                                "total": len(expected_rows), "decoded": len(expected_rows), "partial": 0, "unknown": 0,
                            })
                        else:
                            statuses = ["unknown"] if route == "MIL" else ["unknown", "unknown", "decoded"]
                            self.assertEqual([record["status"] for record in records], statuses)
                            self.assertEqual(ir["coverage"]["record"], {
                                "total": len(statuses), "decoded": int(route == "LDDB"),
                                "partial": 0, "unknown": 1 if route == "MIL" else 2,
                            })
                            self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED"
                                                for item in ir["pous"][0]["findings"]))
                        self.assertEqual(source.read_bytes(), before)

    def test_sw_mov_near_matches_remain_unmined(self) -> None:
        for route, fixture in (("MIL", SW_MOV_MIL), ("LDDB", SW_MOV_LDDB)):
            for reverse in (False, True):
                raw = fixture.replace("MOV:D:SW:", "MOV:SW:D:") if reverse else fixture
                for altered in (
                    raw.replace("a=5:", "a=-1:"),
                    raw.replace("a=10:", "a=-1:"),
                    raw.replace("A16", "A32"),
                    raw.replace("vt=A16}", "vt=A16:unknown=1}"),
                    raw.replace("ct=a", "ct=p"),
                    raw.replace("MOV:", "DMOV:"),
                    raw.replace(":SW:", ":SW:SW:"),
                    raw.replace(":D:", ":SW:"),
                    raw.replace("vt=nn", "vt=UNMINED"),
                    raw.replace("s=#:a=10", "s=0:a=10"),
                    raw.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=c{s=#:v=2}}"),
                    raw.replace("d{s=#:a=10:vt=nn}", "M{b=d{s=#:a=10:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                        .replace(":SW:", ":SW:Zs:"),
                    raw.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
                ):
                    with self.subTest(route=route, reverse=reverse, raw=altered), self.assertRaises(MiningRequired):
                        if route == "MIL":
                            _decode_mil(altered, 1)
                        else:
                            _decode_lddb(altered, 0, 2)
        for raw in (SB_CONTACT_MIL.replace(":SB:", ":SW:"), SB_OUT_MIL.replace(":SB:", ":SW:")):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_mil(raw, 1)
        for raw in (
            SB_CONTACT_LDDB.replace(":SB:", ":SW:"),
            SB_OUT_LDDB.replace(":SB:", ":SW:"),
            SW_MOV_LDDB.replace("MOV:D:SW:", "Zs:MOV:D:SW:"),
            SW_MOV_LDDB.replace("e{s=ce{", "e{s=ce{unknown=1:"),
            SW_MOV_LDDB.replace("}:pos=", "}:unknown=1:pos="),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)
        with self.assertRaises(MiningRequired):
            _format_operand(["SW"], ("scalar", (255,)))

    def test_installed_cli_sw_mov_routes_preserve_source_and_unknown_records(self) -> None:
        for route, fixture in (("MIL", SW_MOV_MIL), ("LDDB", SW_MOV_LDDB)):
            for reverse in (False, True):
                for expected in ("decoded", "unknown"):
                    raw = fixture.replace("MOV:D:SW:", "MOV:SW:D:") if reverse else fixture
                    raw = raw.replace("a=5:" if reverse else "a=10:", "a=256:")
                    if expected == "unknown":
                        raw = raw.replace("A16", "A32")
                    with self.subTest(route=route, reverse=reverse, expected=expected), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = root / "synthetic-sw.gx3"
                        if route == "MIL":
                            synthetic_gx3(source, mil_mov=True, mil_source=raw)
                        else:
                            synthetic_gx3(source, lddb_source=raw)
                        before = source.read_bytes()
                        output = root / "output"
                        result = subprocess.run(
                            [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                             "--phase2-output", str(output)],
                            cwd=root, capture_output=True, text=True, timeout=30,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                        records = ir["pous"][0]["records"]
                        if expected == "decoded":
                            # Match the existing MIL/DMOV Neutral IR continuation contract:
                            # each operand has its own row, linked to the MOV base row.
                            tokens = ["SW100", "D10"] if reverse else ["D5", "SW100"]
                            expected_rows = [
                                ("instruction", "MOV", [tokens[0]]),
                                ("continuation", None, [tokens[1]]),
                            ]
                            base_index = 0 if route == "MIL" else 1
                            if route == "LDDB":
                                expected_rows.insert(0, ("instruction", "LD", ["M7"]))
                                expected_rows.append(("instruction", "END", []))
                            self.assertEqual([
                                (record["kind"], record["opcode"],
                                 [operand["raw_token"] for operand in record["operands"]])
                                for record in records
                            ], expected_rows)
                            self.assertEqual([record["status"] for record in records],
                                             ["decoded"] * len(expected_rows))
                            self.assertEqual([record["continues_record_id"] for record in records],
                                             [None, records[0]["record_id"]] if route == "MIL"
                                             else [None, None, records[base_index]["record_id"], None])
                            self.assertEqual(ir["coverage"]["record"], {
                                "total": len(expected_rows), "decoded": len(expected_rows),
                                "partial": 0, "unknown": 0,
                            })
                        else:
                            statuses = ["unknown"] if route == "MIL" else ["unknown", "unknown", "decoded"]
                            self.assertEqual([record["status"] for record in records], statuses)
                            self.assertEqual(ir["coverage"]["record"], {
                                "total": len(statuses), "decoded": int(route == "LDDB"),
                                "partial": 0, "unknown": 1 if route == "MIL" else 2,
                            })
                            self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED"
                                                for item in ir["pous"][0]["findings"]))
                        self.assertEqual(source.read_bytes(), before)

    def test_sb_mil_near_matches_remain_unmined(self) -> None:
        for fixture in (SB_CONTACT_MIL, SB_OUT_MIL):
            for raw in (
                fixture.replace("a=5:", "a=-1:"),
                fixture.replace("Abl", "A16"),
                fixture.replace("Abl", "Abl:unknown=1"),
                fixture.replace("ct=a", "ct=p"),
                fixture.replace("vt=nn", "vt=UNMINED"),
                fixture.replace(":SB:", ":SW:"),
                fixture.replace(":SB:", ":SB:SB:"),
                fixture.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=c{s=#:v=2}}")
                    .replace(":SB:", ":SB:Ks:"),
                fixture.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                    .replace(":SB:", ":SB:Zs:"),
                fixture.replace("s=#:a=5", "s=0:a=5"),
                fixture.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
            ):
                with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                    _decode_mil(raw, 1)
        for raw in (
            SB_CONTACT_MIL.replace("lt=l", "lt=o"),
            SB_CONTACT_MIL.replace("A:SB:", "B:SB:"),
            SB_CONTACT_MIL.replace("A:SB:", "OUT:SB:"),
            SB_OUT_MIL.replace("OUT:SB:", "RST:SB:"),
            SB_OUT_MIL.replace("OUT:SB:", "A:SB:"),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_mil(raw, 1)
        with self.assertRaises(MiningRequired):
            _format_operand(["SB"], ("scalar", (255,)))

    def test_sb_lddb_near_matches_remain_unmined(self) -> None:
        for fixture in (SB_CONTACT_LDDB, SB_OUT_LDDB):
            for raw in (
                fixture.replace("a=5:", "a=-1:"),
                fixture.replace("Abl", "A16"),
                fixture.replace("vt=Abl}", "vt=Abl:unknown=1}"),
                fixture.replace("ct=a", "ct=p"),
                fixture.replace("vt=nn", "vt=UNMINED"),
                fixture.replace(":SB:", ":SW:"),
                fixture.replace(":SB:", ":SB:SB:"),
                fixture.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=c{s=#:v=2}}")
                    .replace(":SB:", ":SB:Ks:"),
                fixture.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=d{s=#:a=1:vt=nn}}")
                    .replace(":SB:", ":SB:Zs:"),
                fixture.replace("s=#:a=5", "s=0:a=5"),
                fixture.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
                fixture.replace("e{s=ce{", "e{s=ce{unknown=1:"),
                fixture.replace("}:pos=", "}:unknown=1:pos="),
            ):
                with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                    _decode_lddb(raw, 0, 2)
        for raw in (
            SB_CONTACT_LDDB.replace("a:SB:", "b:SB:"),
            SB_CONTACT_LDDB.replace("a:SB:", "c:SB:"),
            SB_CONTACT_LDDB.replace("a:SB:", "Zs:a:SB:"),
            SB_OUT_LDDB.replace("c:SB:", "RST:SB:"),
            SB_OUT_LDDB.replace("c:SB:", "OUT__16:SB:"),
            SB_OUT_LDDB.replace("c:SB:", "a:SB:"),
            SB_OUT_LDDB.replace("c:SB:", "Zs:c:SB:"),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)

    def test_installed_cli_sb_routes_preserve_source_and_unknown_records(self) -> None:
        for route, fixture, sb_index, opcode in (
            ("MIL", SB_CONTACT_MIL, 0, "LD"),
            ("MIL", SB_OUT_MIL, 0, "OUT"),
            ("LDDB", SB_CONTACT_LDDB, 0, "LD"),
            ("LDDB", SB_OUT_LDDB, 1, "OUT"),
        ):
            for expected in ("decoded", "unknown"):
                raw = fixture.replace("a=5:", "a=256:")
                if expected == "unknown":
                    raw = raw.replace("Abl", "A16")
                with self.subTest(route=route, opcode=opcode, expected=expected), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "synthetic-sb.gx3"
                    if route == "MIL":
                        synthetic_gx3(source, mil_mov=True, mil_source=raw)
                    else:
                        synthetic_gx3(source, lddb_source=raw)
                    before = source.read_bytes()
                    output = root / "output"
                    result = subprocess.run(
                        [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                         "--phase2-output", str(output)],
                        cwd=root, capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                    records = ir["pous"][0]["records"]
                    statuses = [expected] if route == "MIL" else [expected, expected, "decoded"]
                    self.assertEqual([record["status"] for record in records], statuses)
                    if expected == "decoded":
                        self.assertEqual(records[sb_index]["opcode"], opcode)
                        self.assertEqual(records[sb_index]["operands"][0]["raw_token"], "SB100")
                        if route == "LDDB":
                            self.assertEqual(records[1 - sb_index]["operands"][0]["raw_token"],
                                             "M10" if sb_index == 0 else "M256")
                            self.assertEqual(records[-1]["opcode"], "END")
                    else:
                        self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED"
                                            for item in ir["pous"][0]["findings"]))
                    self.assertEqual(source.read_bytes(), before)

    def test_counter_scalar_contact_output_reset(self) -> None:
        for address in (0, 5, 255):
            for mil, opcode, operands in (
                (C_CONTACT_MIL, "LD", [f"C{address}"]),
                (C_OUT_MIL, "OUT", [f"C{address}", "K3"]),
                (C_RESET_MIL, "RST", [f"C{address}"]),
            ):
                with self.subTest(address=address, opcode=opcode):
                    self.assertEqual(_decode_mil(mil.replace("a=5:", f"a={address}:"), 1), [
                        {"kind": "instruction", "opcode": opcode, "operands": operands, "text": None}
                    ])

    def test_counter_scalar_near_matches_remain_unmined(self) -> None:
        for mil in (
            C_CONTACT_MIL.replace("a=5:", "a=-1:"),
            C_CONTACT_MIL.replace("lt=l", "lt=o"),
            C_CONTACT_MIL.replace("ct=a", "ct=p"),
            C_CONTACT_MIL.replace("Abl", "A16"),
            C_CONTACT_MIL.replace("vt=nn", "vt=UNMINED"),
            C_OUT_MIL.replace("A16", "A32"),
            C_OUT_MIL.replace("ct=a", "ct=p"),
            C_OUT_MIL.replace("K_1:", "K_2:"),
            C_OUT_MIL.replace("v=3:", "v=-1:"),
            C_RESET_MIL.replace("RST:C:", "OUT:C:"),
            C_OUT_MIL.replace("OUT:C:", "OUT:LC:"),
            C_RESET_MIL.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=c{s=#:v=1}}")
                .replace("RST:C:", "RST:C:Zs:"),
        ):
            with self.subTest(mil=mil):
                with self.assertRaises(MiningRequired):
                    _decode_mil(mil, 1)
        with self.assertRaises(MiningRequired):
            _format_operand(["C"], ("scalar", (5,)))

    def test_long_counter_scalar_contact_output_reset(self) -> None:
        for address in (0, 5, 1023):
            for mil, opcode, operands in (
                (LC_CONTACT_MIL, "LD", [f"LC{address}"]),
                (LC_OUT_MIL, "OUT", [f"LC{address}", "K3"]),
                (LC_RESET_MIL, "RST", [f"LC{address}"]),
            ):
                with self.subTest(address=address, opcode=opcode):
                    self.assertEqual(_decode_mil(mil.replace("a=5:", f"a={address}:"), 1), [
                        {"kind": "instruction", "opcode": opcode, "operands": operands, "text": None}
                    ])
        for mil in (
            LC_CONTACT_MIL.replace("lt=l", "lt=o"),
            LC_RESET_MIL.replace("ct=a", "ct=p"),
            LC_OUT_MIL.replace("A32", "A16"),
            LC_OUT_MIL.replace("K_2:", "K_1:"),
            LC_OUT_MIL.replace("v=3:", "v=-1:"),
            LC_OUT_MIL.replace("OUT:LC:", "OUT:C:"),
            LC_RESET_MIL.replace("a=5:", "a=-1:"),
        ):
            with self.subTest(mil=mil), self.assertRaises(MiningRequired):
                _decode_mil(mil, 1)
        with self.assertRaises(MiningRequired):
            _format_operand(["LC"], ("scalar", (5,)))

    def test_counter_lddb_contact_output_reset(self) -> None:
        for tag, contact, output, reset in (
            ("C", C_CONTACT_LDDB, C_OUT_LDDB, C_RESET_LDDB),
            ("LC", LC_CONTACT_LDDB, LC_OUT_LDDB, LC_RESET_LDDB),
        ):
            for raw, opcodes, operands in (
                (contact, ["LD", "OUT"], [[tag+"5"], ["M10"]]),
                (output, ["LD", "OUT"], [["M7"], [tag+"5", "K3"]]),
                (reset, ["LD", "RST"], [["M7"], [tag+"5"]]),
            ):
                with self.subTest(tag=tag, raw=raw):
                    rows=_decode_lddb(raw, 0, 2)
                    self.assertEqual([row["opcode"] for row in rows], opcodes)
                    self.assertEqual([row["operands"] for row in rows], operands)

    def test_counter_lddb_near_matches_remain_unmined(self) -> None:
        for raw in (
            C_CONTACT_LDDB.replace("a:C:", "b:C:"),
            C_CONTACT_LDDB.replace("ct=a", "ct=p"),
            C_RESET_LDDB.replace("RST:C:", "c:C:"),
            C_OUT_LDDB.replace("OUT__16", "OUT__32"),
            C_OUT_LDDB.replace("K_1:", "K_2:"),
            C_OUT_LDDB.replace("v=3:", "v=-1:"),
            C_OUT_LDDB.replace("vt=A16", "vt=A32"),
            LC_OUT_LDDB.replace("OUT__32", "OUT__16"),
            LC_OUT_LDDB.replace("K_2:", "K_1:"),
            LC_OUT_LDDB.replace("LC:K_2:", "D:K_2:"),
            LC_OUT_LDDB.replace("vt=A32", "vt=A16"),
            LC_RESET_LDDB.replace("a=5:", "a=-1:"),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)

    def test_counter_lddb_full_element_shape_rejects_extra_fields(self) -> None:
        for fixture in (C_CONTACT_LDDB, C_OUT_LDDB, C_RESET_LDDB,
                        LC_CONTACT_LDDB, LC_OUT_LDDB, LC_RESET_LDDB):
            for raw in (
                fixture.replace("ct=a:as=[", "ct=a:unknown=1:as=["),
                fixture.replace("e{s=ce{", "e{s=ce{unknown=1:"),
                fixture.replace("vt=Abl}", "vt=Abl:unknown=1}"),
                fixture.replace("}:pos=", "}:unknown=1:pos="),
            ):
                with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                    _decode_lddb(raw, 0, 2)

    def test_counter_lddb_indexed_operation_marker_remains_unmined(self) -> None:
        for raw in (
            C_CONTACT_LDDB.replace("a:C:", "Zs:a:C:"),
            C_RESET_LDDB.replace("RST:C:", "Zs:RST:C:"),
            C_OUT_LDDB.replace("OUT__16:C:", "Zs:OUT__16:C:"),
            LC_CONTACT_LDDB.replace("a:LC:", "Zs:a:LC:"),
            LC_RESET_LDDB.replace("RST:LC:", "Zs:RST:LC:"),
            LC_OUT_LDDB.replace("OUT__32:LC:", "Zs:OUT__32:LC:"),
        ):
            with self.subTest(raw=raw), self.assertRaises(MiningRequired):
                _decode_lddb(raw, 0, 2)

    def test_f_out_keeps_unmined_forms_closed(self) -> None:
        for mil in (
            F_OUT_MIL.replace("a=64:", "a=-1:"),
            F_OUT_MIL.replace("Abl", "A16"),
            F_OUT_MIL.replace("ct=a", "ct=p"),
            F_OUT_MIL.replace("OUT:F:", "OUT:UNMINED:"),
            F_OUT_MIL.replace("OUT:F:", "MOV:F:"),
            F_OUT_MIL.replace("vt=nn", "vt=UNMINED"),
            F_OUT_MIL.replace("d{s=#:a=64:vt=nn}", "M{b=d{s=#:a=64:vt=nn}:m=c{s=#:v=2}}")
                .replace("OUT:F:", "OUT:F:Ks:"),
        ):
            with self.subTest(mil=mil):
                with self.assertRaises(MiningRequired):
                    _decode_mil(mil, 1)
        with self.assertRaises(MiningRequired):
            _format_operand(["F"], ("scalar", (64,)))

    def test_installed_cli_f_out_preserves_input_and_unknown_records(self) -> None:
        for mil, expected in ((F_OUT_MIL, "decoded"),
                              (F_OUT_MIL.replace("Abl", "UNMINED"), "unknown")):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "synthetic-f.gx3"
                synthetic_gx3(source, mil_mov=True, mil_source=mil)
                before = source.read_bytes()
                output = root / "output"
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                     "--phase2-output", str(output)],
                    cwd=root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                records = ir["pous"][0]["records"]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["status"], expected)
                self.assertEqual(ir["coverage"]["record"], {
                    "total": 1, "decoded": int(expected == "decoded"),
                    "partial": 0, "unknown": int(expected == "unknown"),
                })
                if expected == "decoded":
                    self.assertEqual(records[0]["opcode"], "OUT")
                    self.assertEqual(records[0]["operands"][0]["raw_token"], "F64")
                else:
                    self.assertTrue(any(item["finding_code"] == "MINING_REQUIRED"
                                        for item in ir["pous"][0]["findings"]))
                self.assertEqual(source.read_bytes(), before)

    def test_lz_dmov_requires_exact_32bit_scalar_signature(self) -> None:
        mil = MOV_MIL.replace("MOV:D:D", "MOV:LZ:D").replace("A16", "A32").replace("s=0", "s=#").replace("op=0", "op=#")
        self.assertEqual(_decode_mil(mil, 1), [
            {"kind": "instruction", "opcode": "DMOV", "operands": ["LZ5", "D10"], "text": None}
        ])
        for altered in (
            mil.replace("A32", "A16"), mil.replace("ct=a", "ct=p"),
            mil.replace("a=5", "a=-1"), mil.replace("LZ:", "UNMINED:"),
            mil.replace("vt=nn", "vt=UNMINED"),
            mil.replace("d{s=#:a=5:vt=nn}", "M{b=d{s=#:a=5:vt=nn}:m=c{s=#:v=2}}"),
        ):
            with self.subTest(mil=altered), self.assertRaises(MiningRequired):
                _decode_mil(altered, 1)
        with self.assertRaises(MiningRequired):
            _format_operand(["LZ"], ("scalar", (0,)))

    def test_installed_cli_lz_dmov_both_directions_and_preservation(self) -> None:
        for address in (0, 1):
            for source_tag, target_tag in (("LZ", "D"), ("D", "LZ")):
                mil = MOV_MIL.replace("MOV:D:D", f"MOV:{source_tag}:{target_tag}")
                mil = mil.replace("A16", "A32").replace("s=0", "s=#").replace("op=0", "op=#")
                mil = mil.replace("a=5:", f"a={address}:").replace("a=10:", f"a={address}:")
                with self.subTest(address=address, direction=(source_tag, target_tag)), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory);source = root / "synthetic-lz.gx3"
                    synthetic_gx3(source, mil_mov=True, mil_source=mil)
                    before = source.read_bytes();output = root / "output"
                    result = subprocess.run(
                        [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                         "--phase2-output", str(output)], cwd=root, capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                    records = ir["pous"][0]["records"]
                    self.assertEqual(records[0]["opcode"], "DMOV")
                    self.assertEqual([record["operands"][0]["raw_token"] for record in records],
                                     [f"{tag}{address}" for tag in (source_tag, target_tag)])
                    self.assertEqual(records[1]["continues_record_id"], records[0]["record_id"])
                    self.assertEqual(ir["coverage"]["record"], {"total": 2, "decoded": 2, "partial": 0, "unknown": 0})
                    self.assertEqual(source.read_bytes(), before)

    def test_w_scalar_uses_hexadecimal_addresses(self) -> None:
        for address, token in ((0, "W0"), (0xFF, "WFF"), (0x100, "W100")):
            with self.subTest(address=address):
                self.assertEqual(_format_operand(["W"], ("scalar", (address,))), (token, 1))

    def test_w_does_not_admit_unmined_forms(self) -> None:
        for tags, operand in (
            (["W"], ("scalar", (-1,))),
            (["W"], ("scalar", (255, 1))),
            (["W", "Zs"], ("k_device", (255, 1))),
            (["SW"], ("scalar", (255,))),
            (["UNMINED"], ("scalar", (255,))),
        ):
            with self.subTest(tags=tags, operand=operand):
                with self.assertRaises(MiningRequired):
                    _format_operand(tags, operand)
        with self.assertRaises(MiningRequired):
            _decode_mil(MOV_MIL.replace("MOV:D:D", "MOV:W:D").replace("A16", "UNMINED"), 1)

    def test_installed_cli_w_mov_both_directions_preserves_input(self) -> None:
        for address in (0xFF, 0x100):
            for source_tag, target_tag in (("W", "D"), ("D", "W")):
                with self.subTest(address=address, direction=(source_tag, target_tag)):
                    mil = MOV_MIL.replace("MOV:D:D", f"MOV:{source_tag}:{target_tag}")
                    mil = mil.replace("a=5:", f"a={address}:").replace("a=10:", f"a={address}:")
                    tokens = [f"W{address:X}" if tag == "W" else f"D{address}"
                              for tag in (source_tag, target_tag)]
                    self.assertEqual(_decode_mil(mil, 1), [
                        {"kind": "instruction", "opcode": "MOV", "operands": tokens, "text": None}
                    ])
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = root / "synthetic-w.gx3"
                        synthetic_gx3(source, mil_mov=True, mil_source=mil)
                        before = source.read_bytes()
                        output = root / "output"
                        result = subprocess.run(
                            [sys.executable, "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source),
                             "--phase2-output", str(output)],
                            cwd=root, capture_output=True, text=True, timeout=30,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                        records = ir["pous"][0]["records"]
                        self.assertEqual([item["operands"][0]["raw_token"] for item in records], tokens)
                        self.assertEqual(records[1]["continues_record_id"], records[0]["record_id"])
                        self.assertEqual(ir["coverage"]["record"],
                                         {"total": 2, "decoded": 2, "partial": 0, "unknown": 0})
                        self.assertEqual(source.read_bytes(), before)

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
