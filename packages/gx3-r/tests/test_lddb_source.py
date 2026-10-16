"""Synthetic R04 empty-MIL source-path boundaries; no engineering inputs."""
import hashlib
import sqlite3
import unittest
from unittest.mock import patch

from gx3_r_parser_toolkit import parser
from gx3_r_parser_toolkit.lddb import END, LddbSourceError, decode_empty_mil


def contact(kind="a", source="10", target="20"):
    return ("V1:4:1:1:1:1:" + kind + ":M:c:M:cb{fg=fg{dim=2x1:es=[e{s=ce{op=ct{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a="
            + source + ":vt=nn}]}:pos=0,0}:e{s=ce{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:args=[d{s=#:a="
            + target + ":vt=nn}]}:pos=1,0}]}}")


def database(tables):
    db = sqlite3.connect(":memory:")
    try:
        for name, (columns, rows) in tables.items():
            db.execute('CREATE TABLE "' + name + '" (' + ','.join('"' + col + '"' for col in columns) + ')')
            db.executemany('INSERT INTO "' + name + '" VALUES (' + ','.join('?' for _ in columns) + ')', rows)
        return db.serialize()
    finally:
        db.close()


class Archive:
    input_sha256 = "a" * 64

    def __init__(self, *, data=None, blocks=None, steps=None, ladder=None, mil=()):
        blocks = blocks if blocks is not None else [(500000.0, "first", 2, 42), (1000000.0, "end", 2, 42)]
        steps = steps if steps is not None else [(500000.0, 0, "first", 0, 1), (500000.0, 0, "first", 1, 1), (1000000.0, 0, "end", 0, 2)]
        ladder = ladder if ladder is not None else [("first", 500000.0, 0, data if data is not None else contact()), ("end", 1000000.0, 5, END)]
        self.entries = {
            "1_StepInfo.db": database({"T_Block": (("Pos", "BlockID", "StepSize", "BodyID"), blocks),
                "T_Step": (("Pos", "ElementIDMacroFB", "BlockID", "MilID", "StepSize"), steps)}),
            "pair_LDDB.db": database({"LadderBlocks": (("id", "pos", "blocktype", "data"), ladder)}),
            "pair_MilDB.db": database({"MIL": (("id", "pos", "data"), mil)}),
        }

    def digest(self, name):
        return hashlib.sha256(self.entries[name]).hexdigest()


POU = {"pou_id": "1", "stepinfo": "1_StepInfo.db"}
PAIR = ("pair_LDDB.db", "pair_MilDB.db")


class LddbSourceTests(unittest.TestCase):
    def reject(self, archive):
        with self.assertRaises(LddbSourceError) as caught:
            decode_empty_mil(archive, POU, *PAIR)
        self.assertTrue(caught.exception.locator)
        self.assertTrue(caught.exception.code.startswith("LDDB_"))

    def test_ld_ldi_transactional_records_and_actual_lddb_provenance(self):
        for kind, opcode in (("a", "LD"), ("b", "LDI")):
            archive = Archive(data=contact(kind))
            records, findings = parser._decode_pou(archive, POU, [PAIR])
            self.assertEqual([r["opcode"] for r in records], [opcode, "OUT", "END"])
            self.assertEqual([r["step"] for r in records], [0, 1, 2])
            self.assertEqual([r["operands"][0]["raw_token"] for r in records[:2]], ["M10", "M20"])
            self.assertIn("LDDB_SOURCE_ONLY_EMPTY_MIL", findings[0]["reason"])
            for record in records:
                provenance = record["provenance"]
                self.assertEqual(provenance["source_entry"], PAIR[0])
                self.assertEqual(provenance["source_store"], "LadderBlocks")
                self.assertEqual(provenance["source_digest"], archive.digest(PAIR[0]))
                self.assertIn("pou:1/", provenance["source_locator"])

    def test_payload_grammar_rejects_extensions_and_unobserved_forms(self):
        original = contact()
        for data in (original + "trailing", original + "\n", original.replace("dim=2x1", "dim=2x2"),
                     original.replace("pos=1,0", "pos=1,1"), original.replace(":M:", ":D:", 1),
                     contact("c"), contact(source="-1"), contact(source="4294967296"),
                     contact(source="9" * 100), original.replace("ct=a", "ct=b", 1), "malformed"):
            with self.subTest(data=data[:40]):
                self.reject(Archive(data=data))
        self.assertEqual(decode_empty_mil(Archive(data=contact(source="4294967295")), POU, *PAIR)[0]["operands"][0]["raw_token"], "M4294967295")

    def test_duplicate_ids_positions_and_body_relations_reject(self):
        for blocks in ([(1.0, "first", 2, 1), (2.0, "first", 2, 1)],
                       [(1.0, "first", 2, 1), (1.0, "end", 2, 1)],
                       [(float("inf"), "first", 2, 1), (2.0, "end", 2, 1)],
                       [(500000.0, "first", 2, 1), (1000000.0, "end", 2, 2)]):
            self.reject(Archive(blocks=blocks))
        self.reject(Archive(ladder=[("first", 500000.0, 0, contact()), ("first", 1000000.0, 5, END)]))
        self.reject(Archive(ladder=[("first", 1.0, 0, contact()), ("end", 1000000.0, 5, END)]))

    def test_step_mismatch_duplicate_orphan_and_wrong_end_reject_without_partial_output(self):
        for steps in ([(500000.0, 0, "first", 0, 1), (500000.0, 0, "first", 0, 1), (1000000.0, 0, "end", 0, 2)],
                      [(500000.0, 0, "first", 0, 2), (1000000.0, 0, "end", 0, 2)],
                      [(500000.0, 1, "first", 0, 1), (500000.0, 0, "first", 1, 1), (1000000.0, 0, "end", 0, 2)],
                      [(500000.0, 0, "orphan", 0, 1)], []):
            self.reject(Archive(steps=steps))
        archive = Archive(ladder=[("first", 500000.0, 0, contact()), ("end", 1000000.0, 5, END + "x")])
        records, findings = parser._decode_pou(archive, POU, [PAIR])
        self.assertEqual(records, [])
        self.assertIn("LDDB_FINAL_END_UNVERIFIED", findings[0]["reason"])

    def test_nonempty_wrong_mil_and_ambiguous_pair_never_invoke_fallback(self):
        archive = Archive(mil=[("first", 500000.0, "wrong")])
        with patch.object(parser, "decode_empty_mil", side_effect=AssertionError("fallback forbidden")):
            records, findings = parser._decode_pou(archive, POU, [PAIR])
            self.assertEqual(records, [])
            self.assertTrue(findings)
            self.assertEqual(parser._decode_pou(Archive(), POU, [PAIR, PAIR])[0], [])
            nonempty = Archive(mil=[("first", 500000.0, "wrong"), ("end", 1000000.0, "wrong")])
            records, findings = parser._decode_pou(nonempty, POU, [PAIR])
            self.assertTrue(records)
            self.assertTrue(all(record["status"] == "unknown" for record in records))
            self.assertTrue(findings)
        self.reject(archive)

    def test_schema_missing_step_fields_and_mil_table_are_not_empty_success(self):
        archive = Archive()
        archive.entries[POU["stepinfo"]] = database({"T_Block": (("Pos", "BlockID"), [(1, "first"), (2, "end")]),
                                                   "T_Step": (("Pos", "BlockID", "StepSize"), [(1, "first", 1)])})
        self.reject(archive)
        archive = Archive()
        archive.entries[PAIR[1]] = database({"OTHER": (("id",), [])})
        self.reject(archive)

    def test_shared_candidate_is_still_blocked_by_parse(self):
        archive = Archive()
        topology = {"pous": [{**POU}, {**POU, "pou_id": "2"}]}
        with patch.object(parser, "SafeGx3Archive", return_value=archive), \
             patch.object(parser, "_detect_profile", return_value=({"decision": "SUPPORTED"}, [])), \
             patch.object(parser, "_topology", return_value=(topology, [])), \
             patch.object(parser, "_candidate_pairs", return_value=[PAIR]), \
             patch.object(parser, "_decode_pou", side_effect=AssertionError("shared pair must be blocked")), \
             patch.object(parser, "sha256_file", return_value=archive.input_sha256), \
             patch.object(parser, "_envelope", return_value={}) as envelope, \
             patch.object(parser, "validate_ir"):
            parser.parse("unused")
        self.assertTrue(all(pou["records"] == [] for pou in envelope.call_args.args[2]))

    def test_real_tables_required_for_mil_step_and_ladder_views(self):
        for entry, table in ((PAIR[1], "MIL"), (POU["stepinfo"], "T_Block"),
                             (POU["stepinfo"], "T_Step"), (PAIR[0], "LadderBlocks")):
            with self.subTest(table=table):
                archive = Archive()
                db = sqlite3.connect(":memory:")
                try:
                    db.deserialize(archive.entries[entry])
                    if table == "MIL":
                        db.execute("INSERT INTO MIL VALUES ('hidden',1,'nonempty')")
                    db.execute('ALTER TABLE "' + table + '" RENAME TO backing')
                    db.execute('CREATE VIEW "' + table + '" AS SELECT * FROM backing' +
                               (' WHERE 0' if table == 'MIL' else ''))
                    db.commit()
                    archive.entries[entry] = db.serialize()
                finally:
                    db.close()
                with self.assertRaises(LddbSourceError) as caught:
                    decode_empty_mil(archive, POU, *PAIR)
                self.assertEqual(caught.exception.source_entry, entry)
                self.assertEqual(caught.exception.code, "LDDB_SOURCE_NOT_TABLE")
                records, findings = parser._decode_pou(archive, POU, [PAIR])
                self.assertEqual(records, [])
                self.assertEqual(findings[0]["digest"], archive.digest(entry))
                self.assertIn(entry + ":" + table, findings[0]["locator"])

    def test_empty_mil_uses_bounded_path_before_legacy_eager_reads(self):
        archive = Archive()
        with patch("gx3_r_parser_toolkit.lddb.MAX_ROWS", 2), \
             patch.object(parser, "sqlite_connection", side_effect=AssertionError("legacy eager read forbidden")):
            records, findings = parser._decode_pou(archive, POU, [PAIR])
        self.assertEqual(records, [])
        self.assertEqual(findings[0]["reason"], "LDDB_SOURCE_ROW_LIMIT")
        self.assertEqual(findings[0]["digest"], archive.digest(POU["stepinfo"]))

    def test_nonempty_mil_is_not_subject_to_new_fallback_row_cap(self):
        archive = Archive(mil=[("first", 500000.0, "wrong"), ("end", 1000000.0, "wrong")])
        with patch("gx3_r_parser_toolkit.lddb.MAX_ROWS", 1):
            records, findings = parser._decode_pou(archive, POU, [PAIR])
        self.assertTrue(records)
        self.assertTrue(findings)
        self.assertTrue(all(record["status"] == "unknown" for record in records))

    def test_absent_error_carrier_has_explicit_archive_digest_scope(self):
        archive = Archive()
        del archive.entries[POU["stepinfo"]]
        records, findings = parser._decode_pou(archive, POU, [PAIR])
        self.assertEqual(records, [])
        self.assertIn("source entry absent; digest_scope=archive", findings[0]["reason"])
        self.assertEqual(findings[0]["digest"], archive.input_sha256)


if __name__ == "__main__":
    unittest.main()
