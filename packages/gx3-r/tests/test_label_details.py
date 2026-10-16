"""Synthetic disposable inputs for the separate label-details contract."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from gx3_r_parser_toolkit import label_details, parser
from gx3_r_parser_toolkit.archive import ArchiveError
from gx3_r_parser_toolkit.objects import TABLES


def fixture_tables():
    return {
        "LabelTbl": [("sample-local", 5121)],
        "RowTbl": [("sample-local", 1, 1, 1, "0", 0, 0)],
        "ColumnDataTbl": [
            ("sample-local", 1, 1, "VAR", 4),
            ("sample-local", 1, 2, "ExampleFlag", 0),
            ("sample-local", 1, 3, "", 1),
            ("sample-local", 1, 9, "Example comment", 0),
        ],
    }


def database(tables, *, view=None, extra_column=False, assigned=False):
    db = sqlite3.connect(":memory:")
    try:
        for name, rows in tables.items():
            columns = TABLES[name]
            declaration = ','.join('"' + column + '"' for column in columns)
            if extra_column and name == "RowTbl":
                declaration += ',"Unobserved"'
                rows = [(*row, "raw extra value") for row in rows]
            if name == view:
                db.execute('CREATE TABLE "view_source" (' + declaration + ')')
                db.executemany('INSERT INTO "view_source" VALUES (' + ','.join('?' for _ in columns) + ')', rows)
                db.execute('CREATE VIEW "' + name + '" AS SELECT * FROM view_source')
            else:
                db.execute('CREATE TABLE "' + name + '" (' + declaration + ')')
                width = len(columns) + int(extra_column and name == "RowTbl")
                db.executemany('INSERT INTO "' + name + '" VALUES (' + ','.join('?' for _ in range(width)) + ')', rows)
        if assigned:
            db.execute('CREATE TABLE DeviceAssignTbl (LabelID,RowID,MELSECDevice,ManualSet)')
            db.execute('INSERT INTO DeviceAssignTbl VALUES (?,?,?,?)', ("sample-local", 1, "LV:0.0", 0))
        db.commit()
        return db.serialize()
    finally:
        db.close()


class LabelDetailsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "synthetic-labels.gx3"

    def write(self, tables=None, *, cpu="R04", include_label=True, **options):
        config = '<Root><Config Unit="' + cpu + '" UnitId="4097"/></Root>'
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("Config.xml", config)
            archive.writestr("!!Config.xml", config)
            if include_label:
                archive.writestr("LabelData.db", database(tables if tables is not None else fixture_tables(), **options))
        return self.source

    def read(self, tables=None, **options):
        return label_details.parse_label_details(self.write(tables, **options))

    def unknown(self, record):
        self.assertEqual("UNKNOWN", record["status"])
        self.assertTrue(all(value == {"status": "UNKNOWN", "value": None}
                            for value in record["attributes"].values()))

    def test_observed_attributes_are_separate_deterministic_and_digest_bound(self):
        source = self.write()
        before_bytes = source.read_bytes()
        before_ir = parser.parse(source)
        result = label_details.parse_label_details(source)
        self.assertEqual(result, label_details.parse_label_details(source))
        self.assertEqual(before_ir, parser.parse(source))
        self.assertEqual(before_bytes, source.read_bytes())
        self.assertEqual(hashlib.sha256(before_bytes).hexdigest(), result["input"]["sha256"])
        self.assertEqual("plcman.gx3.r-label-details", result["schema_name"])
        self.assertFalse(result["project_complete"])
        self.assertEqual({"total": 1, "partial": 1, "unknown": 0}, result["counts"])
        record = result["records"][0]
        supported = {key: value["value"] for key, value in record["attributes"].items()
                     if value["status"] == "SUPPORTED"}
        self.assertEqual({"class": "VAR", "label_name": "ExampleFlag", "data_type": "BOOL",
                          "comment": "Example comment"}, supported)
        self.assertEqual(27, len(record["attributes"]))
        self.assertEqual(23, sum(value == {"status": "UNKNOWN", "value": None}
                                 for value in record["attributes"].values()))
        self.assertEqual({"status": "UNKNOWN", "pou_id": None}, record["owner"])
        for name in label_details.LABEL_TABLES:
            self.assertEqual(list(range(len(result["raw_tables"][name]["rows"]))), record["source_rows"][name])
        json.dumps(result, allow_nan=False)

    def test_internal_device_assignment_never_becomes_official_address(self):
        result = self.read(assigned=True)
        for key in ("assign", "address", "initial_value"):
            self.assertEqual({"status": "UNKNOWN", "value": None}, result["records"][0]["attributes"][key])

    def test_both_observed_states_and_empty_comment(self):
        for state in ((1, "0", 0, 0), (1, "1", 1, 0)):
            with self.subTest(state=state):
                tables = fixture_tables()
                tables["RowTbl"][0] = ("sample-local", 1, 1, *state)
                tables["ColumnDataTbl"][-1] = ("sample-local", 1, 9, "", 0)
                row = self.read(tables)["records"][0]
                self.assertEqual({"status": "SUPPORTED", "value": ""}, row["attributes"]["comment"])
                self.assertEqual("BOOL", row["attributes"]["data_type"]["value"])

    def test_unobserved_class_and_datatype_dual_values_are_unknown(self):
        for column, attribute, text, integer in ((1, "class", "VAR", 4), (3, "data_type", "", 1)):
            for bad_text, bad_integer in ((text, None), (text, str(integer)), (text, float(integer)),
                                           (text, b"1"), ("unobserved", integer), (text, integer + 1)):
                with self.subTest(column=column, text=bad_text, integer=bad_integer):
                    tables = fixture_tables()
                    index = next(i for i, row in enumerate(tables["ColumnDataTbl"]) if row[2] == column)
                    tables["ColumnDataTbl"][index] = ("sample-local", 1, column, bad_text, bad_integer)
                    record = self.read(tables)["records"][0]
                    self.assertEqual({"status": "UNKNOWN", "value": None}, record["attributes"][attribute])

    def test_boolean_float_and_string_are_not_integer_guard_values(self):
        # SQLite stores Python bool as INTEGER. Exercise the decoder boundary
        # directly too, so bool cannot pass Python equality with integer 1/4.
        for integer in (True, False, 1.0, "1"):
            self.assertFalse(label_details._observed_cell([(0, {"ColumnStrValue": "", "ColumnIntValue": integer})], "", 1))
        for table, column, bad_value in (("LabelTbl", "LabelTypeID", 5121.0),
                                         ("RowTbl", "RowID", True), ("RowTbl", "VarType", True)):
            tables = {name: [dict(zip(TABLES[name], row)) for row in rows]
                      for name, rows in fixture_tables().items()}
            tables[table][0][column] = bad_value
            for record in label_details._records(tables, True, "a" * 64):
                self.unknown(record)

    def test_unknown_types_states_columns_and_identity_dual_values(self):
        cases = []
        for value in (5123, 5122, "5121", 5121.0):
            tables = fixture_tables(); tables["LabelTbl"] = [("sample-local", value)]; cases.append(tables)
        tables = fixture_tables(); tables["RowTbl"][0] = ("sample-local", 1, 1, 1, "0", 1, 0); cases.append(tables)
        for column in (2, 9):
            for bad_integer in (None, 1, "0", 0.0):
                tables = fixture_tables()
                index = next(i for i, row in enumerate(tables["ColumnDataTbl"]) if row[2] == column)
                row = tables["ColumnDataTbl"][index]
                tables["ColumnDataTbl"][index] = (*row[:4], bad_integer); cases.append(tables)
        tables = fixture_tables(); tables["ColumnDataTbl"].append(("sample-local", 1, 99, "extra", 0)); cases.append(tables)
        for tables in cases:
            with self.subTest(tables=tables):
                self.unknown(self.read(tables)["records"][0])

    def test_duplicate_rows_cells_metadata_and_semantic_names_are_preserved(self):
        for name in label_details.LABEL_TABLES:
            tables = fixture_tables()
            tables[name].append(tables[name][0])
            result = self.read(tables)
            self.assertEqual(len(tables[name]), len(result["raw_tables"][name]["rows"]))
            for record in result["records"]:
                self.unknown(record)
            if name == "RowTbl":
                self.assertEqual(2, len(result["records"]))
                self.assertEqual(2, len({record["record_id"] for record in result["records"]}))
        tables = fixture_tables()
        second = copy.deepcopy(tables)
        for name in label_details.LABEL_TABLES:
            tables[name] += [("second-local", *row[1:]) for row in second[name]]
        result = self.read(tables)
        self.assertEqual(2, len(result["records"]))
        for record in result["records"]:
            self.unknown(record)

    def test_orphans_and_unreferenced_label_metadata_have_raw_references(self):
        tables = fixture_tables()
        tables["ColumnDataTbl"].append(("orphan-local", 7, 2, "OrphanFlag", 0))
        tables["LabelTbl"].append(("unused-local", 5123))
        tables["RowTbl"].append(("row-only", 5, 5, 1, "0", 0, 0))
        result = self.read(tables)
        self.assertEqual(4, len(result["records"]))
        self.assertEqual({"total": 4, "partial": 1, "unknown": 3}, result["counts"])
        for name in label_details.LABEL_TABLES:
            referenced = {index for record in result["records"] for index in record["source_rows"][name]}
            self.assertEqual(set(range(len(tables[name]))), referenced)

    def test_blob_and_real_raw_values_have_deterministic_json_encoding(self):
        tables = fixture_tables()
        tables["ColumnDataTbl"].append(("opaque-local", 5, 99, b"\x00\xff", 1.5))
        result = self.read(tables)
        cells = result["raw_tables"]["ColumnDataTbl"]["rows"]
        cell = next(row for row in cells if row["LabelID"] == "opaque-local")
        self.assertEqual({"storage_type": "blob", "hex": "00ff"}, cell["ColumnStrValue"])
        self.assertEqual({"storage_type": "real", "hex": float(1.5).hex()}, cell["ColumnIntValue"])
        json.dumps(result, allow_nan=False)

    def test_missing_extra_schema_and_views_do_not_supply_supported_attributes(self):
        tables = fixture_tables(); del tables["LabelTbl"]
        for kwargs in ({"tables": tables}, {"extra_column": True}, {"view": "ColumnDataTbl"}):
            result = self.read(**kwargs)
            self.assertTrue(any(finding["code"] == "UNKNOWN_SCHEMA" for finding in result["findings"]))
            self.assertTrue(result["records"])
            for record in result["records"]:
                self.unknown(record)
            if "view" in kwargs:
                self.assertNotIn("ColumnDataTbl", result["raw_tables"])

    def test_missing_carrier_and_empty_tables_are_unknown_not_absence_proof(self):
        for result in (self.read(include_label=False), self.read({name: [] for name in label_details.LABEL_TABLES})):
            self.assertEqual("UNKNOWN", result["status"])
            self.assertEqual([], result["records"])
            self.assertFalse(result["project_complete"])

    def test_actual_parser_rejects_invalid_archive_and_non_r_profile(self):
        with self.assertRaises(ArchiveError):
            label_details.parse_label_details(self.write(cpu="Other"))
        self.source.write_bytes(b"invalid synthetic input")
        with self.assertRaises(ArchiveError):
            label_details.parse_label_details(self.source)

    def test_same_file_digest_is_checked_between_and_after_reads(self):
        source = self.write()
        original_parse = parser.parse
        def mismatched_parse(path):
            result = original_parse(path)
            result["input"]["sha256"] = "0" * 64
            return result
        with patch.object(parser, "parse", side_effect=mismatched_parse):
            with self.assertRaisesRegex(ArchiveError, "between"):
                label_details.parse_label_details(source)
        with patch.object(label_details, "sha256_file", return_value="0" * 64):
            with self.assertRaisesRegex(ArchiveError, "during"):
                label_details.parse_label_details(source)

    def test_supplemental_budgets_fail_instead_of_truncating_and_close_database(self):
        source = self.write()
        for name, limit, message in (("MAX_ROWS", 2, "row budget"), ("MAX_TEXT", 20, "text budget"),
                                      ("MAX_TEXT", 1000, "output text budget")):
            with self.subTest(name=name, limit=limit), patch.object(label_details, name, limit):
                with self.assertRaisesRegex(ArchiveError, message):
                    label_details.parse_label_details(source)
        connections = []
        original = label_details.sqlite_connection
        def tracked(data):
            connection = original(data); connections.append(connection); return connection
        with patch.object(label_details, "sqlite_connection", side_effect=tracked):
            label_details.parse_label_details(source)
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")
        connections.clear()
        with patch.object(label_details, "sqlite_connection", side_effect=tracked), patch.object(label_details, "MAX_ROWS", 2):
            with self.assertRaises(ArchiveError):
                label_details.parse_label_details(source)
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
