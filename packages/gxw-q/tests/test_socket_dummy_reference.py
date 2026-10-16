"""Dummy string classification is specific to four observed Q socket forms."""
import unittest
import gxw_reference_ir as ref


def project(opcode, text, profile="mitsubishi.gxw.q.ladder"):
    return ref.project_rows([{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
                              "rows": [(opcode, text, "")]}], input_sha256="a" * 64,
                            profile_id=profile)["occurrences"][0]["operands"]


class SocketDummyTests(unittest.TestCase):
    def test_exact_context_and_no_device_address(self):
        for opcode, text in (("SP.SOCOPEN", "U0 K7 D1000 M110"),
                             ("SP.SOCCLOSE", "U0 K7 D1500 M140"),
                             ("SP.SOCRCV", "U0 K7 D1300 D1400 M130"),
                             ("SP.SOCSND", "U0 K7 D1100 D1200 M120")):
            with self.subTest(opcode=opcode):
                value = project(opcode, text)[0]
                self.assertEqual(("U0", "literal", "decoded", "SOCKET_DUMMY_LITERAL", None),
                                 (value["raw_token"], value["kind"], value["status"], value["access_basis"], value["device"]))
                self.assertEqual("NOT_APPLICABLE", value["coverage"]["state"])
                self.assertIsNone(value["coverage"]["addresses"])

    def test_unverified_context_stays_unknown(self):
        for opcode, text, index in (("MOV", "U0 D0", 0), ("SP.SOCOPEN", "U1 K7 D1000 M110", 0),
                                    ("SP.SOCOPEN", "U0 K7 D1000", 0),
                                    ("SP.SOCOPEN", "K7 U0 D1000 M110", 1),
                                    ("SP.SOCOPEN", "U0 K7 D1000 M110 M120", 0)):
            with self.subTest(text=text):
                self.assertEqual("unknown", project(opcode, text)[index]["status"])
        self.assertEqual("unknown", ref.parse_operand("U0", 0)["status"])
        self.assertEqual("unknown", project("SP.SOCOPEN", "U0 K7 D1000 M110", "other")[0]["status"])

    def test_control_span_is_unknown_even_when_indexed(self):
        result = project("SP.SOCRCV", "U0 K7 D1300Z0 D1400 M130")
        self.assertEqual("UNKNOWN", result[2]["coverage"]["state"])
        self.assertEqual("RESERVED_OR_MIXED_CONTROL_BLOCK", result[2]["coverage"]["reason"])
        self.assertEqual("write", result[2]["access"])

    def test_socket_roles_payload_completion_and_context_guards(self):
        for opcode, text, roles in (("SP.SOCOPEN", "U0 K7 D1000 M110", ["read", "read", "both", "write"]),
                                    ("SP.SOCCLOSE", "U0 K7 D1500 M140", ["read", "read", "write", "write"]),
                                    ("SP.SOCRCV", "U0 K7 D1300 D1400 M130", ["read", "read", "write", "write", "write"]),
                                    ("SP.SOCSND", "U0 K7 D1100 D1200 M120", ["read", "read", "write", "read", "write"])):
            values = project(opcode, text)
            self.assertEqual([v["access"] for v in values], roles)
            self.assertEqual(values[2]["coverage"]["reason"], "RESERVED_OR_MIXED_CONTROL_BLOCK")
            self.assertEqual(values[-1]["coverage"]["reason"], "BIT_RESULT_SPAN")
            self.assertEqual(len(values[-1]["coverage"]["addresses"]), 2)
            self.assertIsNone(values[-1]["coverage"]["word_width"])
            if len(values) == 5:
                self.assertEqual(values[3]["coverage"]["state"], "DYNAMIC")
                self.assertIsNone(values[3]["coverage"]["addresses"])
            for unverified in (project(opcode, text.replace("U0", "U1", 1)), project(opcode, text, "other"),
                               project(opcode, text + " D999")):
                self.assertTrue(all(v["access"] == "unknown" for v in unverified))
                self.assertTrue(all(v["coverage"]["state"] == "UNKNOWN" for v in unverified))
        for dest in ("D100", "D100.0", "K4M100"):
            self.assertEqual(project("SP.SOCOPEN", "U0 K7 D1000 " + dest)[-1]["coverage"]["state"], "UNKNOWN")

    def test_socket_write_constant_unknown_and_unobserved_bit_family(self):
        for opcode, text, position in (("SP.SOCOPEN", "U0 K7 K0 M10", 2),
                                       ("SP.SOCOPEN", "U0 K7 D0 K0", 3),
                                       ("SP.SOCRCV", "U0 K7 D0 K0 M10", 3)):
            value = project(opcode, text)[position]
            self.assertEqual(value["access"], "unknown")
            self.assertEqual(value["access_basis"], "MINED_WRITE_TARGET_UNVERIFIED")
            self.assertEqual(value["coverage"]["reason"], "MINED_WRITE_TARGET_UNVERIFIED")
        for family in ("T", "ST", "C", "X", "Y"):
            value = project("SP.SOCOPEN", "U0 K7 D0 " + family + "0")[-1]
            self.assertEqual(value["coverage"]["reason"], "BIT_RESULT_FORM_UNVERIFIED")
        result = ref.project_rows([{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
                                    "rows": [("SP.SOCOPEN", "", "")]}], input_sha256="a" * 64)
        self.assertEqual(result["analysis"]["state"], "PARTIAL")
        self.assertEqual(result["diagnostics"][0]["reason"], "SOCKET_CONTEXT_UNVERIFIED")
        self.assertEqual(result["diagnostics"][0]["source_locator"], "_hdb/synthetic:row:0")


if __name__ == "__main__":
    unittest.main()
