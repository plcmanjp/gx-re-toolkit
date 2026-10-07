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

from gx3_fx5_profile.decoder import MiningRequired, _decode_lddb, _decode_mil, _format_operand


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
