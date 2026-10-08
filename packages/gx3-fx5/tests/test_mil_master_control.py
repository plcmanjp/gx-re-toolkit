"""Synthetic exact MC/MCR carriers and closed nesting operand boundaries."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from gx3_fx5_profile.decoder import MiningRequired, SCALAR_TAGS, _decode_mil, _format_operand
from gx3_fx5_profile.opcode_signatures import UnknownOpcodeSignature, lookup_mnemonic, mil_stream
from test_installed_semantics import synthetic_gx3


def mc(nesting=0, *, coil=17):
    return (
        "V1:1:1:1:MC:N:M:ms{el=["
        "mc{op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=Abl}]}:"
        f"as=[d{{s=#:a={nesting}:vt=nn}}:d{{s=#:a={coil}:vt=nn}}]}}]}}"
    )


def mcr(nesting=0):
    return (
        "V1:1:1:MCR:N:ms{el=["
        "mc{op=cl{op=#:ct=a:as=[as{vt=A16s}]}:"
        f"as=[d{{s=#:a={nesting}:vt=nn}}]}}]}}"
    )


class MasterControlMilTests(unittest.TestCase):
    def assert_closed(self, data, count=1):
        with self.assertRaises(MiningRequired):
            _decode_mil(data, count)

    def test_mc_lower_boundary(self):
        self.assertEqual(_decode_mil(mc(), 1), [
            {"kind": "instruction", "opcode": "MC", "operands": ["N0", "M17"], "text": None}
        ])

    def test_mcr_lower_boundary(self):
        self.assertEqual(_decode_mil(mcr(), 1), [
            {"kind": "instruction", "opcode": "MCR", "operands": ["N0"], "text": None}
        ])

    def test_documented_upper_boundary_synthetic_only(self):
        self.assertEqual(_decode_mil(mc(14), 1)[0]["operands"], ["N14", "M17"])
        self.assertEqual(_decode_mil(mcr(14), 1)[0]["operands"], ["N14"])

    def test_nesting_is_not_a_generic_scalar_device(self):
        self.assertNotIn("N", SCALAR_TAGS)
        with self.assertRaises(MiningRequired):
            _format_operand(["N"], ("scalar", (0,)))

    def test_invalid_nesting_indices_are_closed(self):
        for value in (-1, 15, 32767):
            for factory in (mc, mcr):
                with self.subTest(value=value, factory=factory):
                    self.assert_closed(factory(value))

    def test_unobserved_coil_family_is_closed(self):
        self.assert_closed(mc().replace("MC:N:M:", "MC:N:L:"))

    def test_unobserved_nesting_family_is_closed(self):
        self.assert_closed(mcr().replace("MCR:N:", "MCR:D:"))

    def test_wrong_width_and_pulse_are_closed(self):
        for factory in (mc, mcr):
            for old, new in (("A16s", "A32s"), ("ct=a", "ct=p")):
                with self.subTest(factory=factory, mutation=new):
                    self.assert_closed(factory().replace(old, new))

    def test_constant_nesting_is_closed(self):
        self.assert_closed(mcr().replace("d{s=#:a=0:vt=nn}", "c{s=#:v=0:si=s}"))

    def test_extra_operand_or_descriptor_is_closed(self):
        self.assert_closed(mcr().replace("MCR:N:", "MCR:N:M:"))
        self.assert_closed(mcr().replace("as=[d{s=#:a=0:vt=nn}]", "as=[d{s=#:a=0:vt=nn}:d{s=#:a=1:vt=nn}]"))

    def test_unobserved_raw_metadata_is_closed(self):
        for factory in (mc, mcr):
            for old, new in (("op=#", "op=9"), ("s=#", "s=1"), ("vt=nn", "vt=nx")):
                with self.subTest(factory=factory, mutation=new):
                    self.assert_closed(factory().replace(old, new))

    def test_unknown_signature_is_not_a_family_rule(self):
        signature = mil_stream(mc().replace("MC:N:M:", "MC:N:L:"))[0][1]
        with self.assertRaises(UnknownOpcodeSignature):
            lookup_mnemonic(signature)

    def test_contact_and_mc_in_same_block_keep_order(self):
        contact = "mc{op=lct{op=#:lt=l:ct=a:as=[as{vt=Abl}]}:as=[d{s=#:a=7:vt=nn}]}"
        data = mc().replace("MC:N:M:", "A:M:MC:N:M:").replace("ms{el=[", "ms{el=[" + contact + ":")
        result = _decode_mil(data, 2)
        self.assertEqual([(row["opcode"], row["operands"]) for row in result], [("LD", ["M7"]), ("MC", ["N0", "M17"])])

    def test_negative_owned_coil_is_closed(self):
        self.assert_closed(mc(coil=-1))


class InstalledMasterControlMilTests(unittest.TestCase):
    def test_installed_cli_coverage_continuation_and_input_preservation(self):
        cases = [(factory(n), opcode, n) for factory, opcode in ((mc, "MC"), (mcr, "MCR")) for n in (0, 14)]
        cases += [(factory(n), None, n) for factory in (mc, mcr) for n in (-1, 15)]
        cases += [(mc().replace("MC:N:M:", "MC:N:L:"), None, 0)]
        for data, opcode, nesting in cases:
            with self.subTest(opcode=opcode, nesting=nesting, data=data), tempfile.TemporaryDirectory(prefix="gx-mc-") as folder:
                root = Path(folder)
                source = root / "synthetic-master-control.gx3"
                synthetic_gx3(source, mil_mov=True, mil_source=data)
                before = source.read_bytes()
                output = root / "ir"
                result = subprocess.run(
                    [sys.executable, "-I", "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source), "--phase2-output", str(output)],
                    cwd=root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((output / "neutral-ir.json").read_text(encoding="utf-8"))
                records = ir["pous"][0]["records"]
                if opcode is None:
                    self.assertEqual([row["status"] for row in records], ["unknown"])
                    self.assertEqual(ir["coverage"]["record"], {"total": 1, "decoded": 0, "partial": 0, "unknown": 1})
                    self.assertTrue(any(row["finding_code"] == "MINING_REQUIRED" for row in ir["pous"][0]["findings"]))
                else:
                    tokens = [f"N{nesting}"] + (["M17"] if opcode == "MC" else [])
                    self.assertEqual([row["operands"][0]["raw_token"] for row in records], tokens)
                    self.assertEqual(records[0]["opcode"], opcode)
                    self.assertEqual([row["status"] for row in records], ["decoded"] * len(tokens))
                    if opcode == "MC":
                        self.assertEqual(records[1]["kind"], "continuation")
                        self.assertEqual(records[1]["continues_record_id"], records[0]["record_id"])
                    self.assertEqual(ir["coverage"]["record"], {"total": len(tokens), "decoded": len(tokens), "partial": 0, "unknown": 0})
                self.assertEqual(source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
