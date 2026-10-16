"""Disposable in-memory SQLite fixtures; no private authority inputs."""
import hashlib
import sqlite3
import unittest
from unittest.mock import patch

from gx3_r_parser_toolkit.archive import ArchiveError
from gx3_r_parser_toolkit.objects import TABLES, read_objects


class Archive:
    input_sha256 = "a" * 64

    def __init__(self, entries):
        self.entries = entries

    def digest(self, name):
        return hashlib.sha256(self.entries[name]).hexdigest()


def database(tables):
    db = sqlite3.connect(":memory:")
    try:
        for name, rows in tables.items():
            columns = TABLES[name]
            db.execute('CREATE TABLE "' + name + '" (' + ",".join('"' + c + '"' for c in columns) + ')')
            db.executemany('INSERT INTO "' + name + '" VALUES (' + ",".join("?" for _ in columns) + ')', rows)
        return db.serialize()
    finally:
        db.close()


def comments(devices, rows):
    return Archive({"Common_DC.db": database({"DEVICE_DATA": devices, "COMMENT_DATA": rows})})


def labels(names=("First",), types=None, extra_rows=(), extra_cells=(), comment_values=None, state=(1, "0", 0, 0), integer_values=None):
    types = types or [5121] * len(names)
    rows = [(str(i), 1, i, *state) for i in range(len(names))]
    cells = [(str(i), 1, col, text, (integer_values or {}).get(col, 0)) for i, name in enumerate(names)
             for col, text in ((2, name), (9, comment_values[i] if comment_values else "comment:" + name))]
    return Archive({"LabelData.db": database({"LabelTbl": [(str(i), t) for i, t in enumerate(types)],
                   "RowTbl": rows + list(extra_rows), "ColumnDataTbl": cells + list(extra_cells)})})


class ObjectTests(unittest.TestCase):
    def test_unobserved_dual_cell_integer_value_is_opaque(self):
        for column in (2, 9):
            for value in (None, 1, -1, "0", 0.0, b"0"):
                with self.subTest(column=column, value=value):
                    rows, findings, counts = read_objects(labels(integer_values={column: value}), "label")
                    self.assertEqual(counts["unknown"], 1)
                    self.assertTrue(rows[0]["label_id"].startswith("MINING_REQUIRED_"))
                    self.assertIn("LabelData.db:RowTbl", findings[0]["locator"])

    def test_second_observed_state_preserves_name_and_comment_but_stays_partial(self):
        for state in ((1, "0", 0, 0), (1, "1", 1, 0)):
            rows, _, counts = read_objects(labels(comment_values=["changed"], state=state), "label")
            self.assertEqual((rows[0]["label_id"], rows[0]["value"]), ("First", "changed"))
            self.assertEqual(counts["partial"], 1)
        for state in ((1, "0", 1, 0), (1, "1", 0, 0), (1, "1", 1, 1)):
            self.assertEqual(read_objects(labels(state=state), "label")[2]["unknown"], 1)

    def conserved(self, result):
        items, findings, counts = result
        self.assertEqual(counts["total"], len(items))
        self.assertEqual(counts["total"], sum(counts[k] for k in ("decoded", "partial", "unknown")))
        key = "device_id" if items and "device_id" in items[0] else "label_id"
        identities = [(r["scope"], r[key], r["language_slot"]) for r in items]
        self.assertEqual(identities, sorted(set(identities)))
        return items, findings, counts

    def test_observed_devices_and_language_slots_preserve_empty_and_unicode(self):
        devices = [(1, 2, 0, 0, 0, 0, 10, 0), (2, 16, 0, 0, 0, 0, 0, 0),
                   (3, 33, 0, 0, 0, 0, 5, 16), (4, 35, 208, 992, 0, 0, 8, 1)]
        rows = [(1, 1, 0, "한글", None), (2, 1, 6, "English", None),
                (3, 2, 0, "", None), (4, 3, 0, "bit", None), (5, 4, 0, "module", None)]
        items, findings, counts = self.conserved(read_objects(comments(devices, rows), "comment"))
        self.assertEqual(counts["decoded"], 0)
        self.assertEqual(counts["partial"], 5)
        self.assertEqual(len(findings), 1)
        self.assertEqual({r["device_id"] for r in items}, {"SM10", "X0", "SD5.F", "U3E0\\G8.0"})
        self.assertEqual(next(r for r in items if r["device_id"] == "X0")["value_state"], "EMPTY_STRING")

    def test_unobserved_code_extended_fields_slots_delete_and_orphans_are_opaque(self):
        devices = [(1, 16, 0, 0, 0, 0, 1, 0), (2, 33, 1, 0, 0, 0, 0, 0),
                   (3, 2, 0, 0, 0, 0, 2, 0), (4, 2, 0, 0, 0, 0, 3, 0)]
        rows = [(1, 1, 0, "x", None), (2, 2, 0, "ext", None), (3, 3, 9, "slot", None),
                (4, 3, 0, "deleted", 0), (5, 999, 0, "orphan", None)]
        items, findings, counts = self.conserved(read_objects(comments(devices, rows), "comment"))
        self.assertEqual(counts["unknown"], 6)
        self.assertEqual(len(findings), 7)
        self.assertTrue(all(r["device_id"].startswith("MINING_REQUIRED_") for r in items))
        self.assertIn("deleted", [row["value"] for row in items])
        self.assertTrue(all(row["value_state"] != "OBJECT_ABSENT" for row in items))

    def test_duplicate_comment_identity_and_device_relation_are_not_dropped(self):
        dev = (1, 2, 0, 0, 0, 0, 1, 0)
        for devices in ([dev], [dev, dev]):
            result = read_objects(comments(devices, [(1, 1, 0, "a", None), (2, 1, 0, "b", None)]), "comment")
            _, _, counts = self.conserved(result)
            self.assertEqual(counts["unknown"], 2)

    def test_local_names_and_comment_changes_stay_partial_without_pou_binding(self):
        a = labels(("First", "Second"))
        first = self.conserved(read_objects(a, "label"))
        self.assertEqual(first[2], {"total": 2, "decoded": 0, "partial": 2, "unknown": 0})
        self.assertEqual({r["label_id"] for r in first[0]}, {"First", "Second"})
        self.assertTrue(all(r["program_id"] is None for r in first[0]))
        self.assertEqual(read_objects(a, "label"), read_objects(a, "label"))
        changed = read_objects(labels(("First", "Second"), comment_values=["changed", ""]), "label")
        self.assertEqual([r["label_id"] for r in first[0]], [r["label_id"] for r in changed[0]])
        self.assertEqual([r["value"] for r in changed[0]], ["changed", ""])

    def test_duplicate_names_unsupported_types_and_orphan_cells_remain_rows(self):
        result = read_objects(labels(("same", "same", "builtin"), types=[5121, 5121, 5123],
                              extra_cells=[("orphan", 99, 2, "lost", None)]), "label")
        _, findings, counts = self.conserved(result)
        self.assertEqual(counts, {"total": 4, "decoded": 0, "partial": 0, "unknown": 4})
        self.assertEqual(len(findings), 4)

    def test_duplicate_rows_cells_and_unobserved_state_are_opaque(self):
        for archive in (labels(extra_rows=[("0", 1, 0, 1, "0", 0, 0)]),
                        labels(extra_cells=[("0", 1, 9, "duplicate", None)]),
                        labels(extra_rows=[("0", 2, 1, 2, "1", 1, 0)])):
            _, _, counts = self.conserved(read_objects(archive, "label"))
            self.assertGreater(counts["unknown"], 0)

    def test_missing_tables_keep_available_raw_rows_and_finding(self):
        archive = Archive({"LabelData.db": database({"RowTbl": [("x", 1, 0, 1, "0", 0, 0)]})})
        _, findings, counts = self.conserved(read_objects(archive, "label"))
        self.assertEqual(counts["unknown"], 1)
        self.assertEqual(len(findings), 2)

    def test_budget_limit_fails_instead_of_truncating(self):
        with patch("gx3_r_parser_toolkit.objects.MAX_ROWS", 1):
            with self.assertRaisesRegex(ArchiveError, "budget"):
                read_objects(labels(), "label")
        with patch("gx3_r_parser_toolkit.objects.MAX_TEXT", 4):
            with self.assertRaisesRegex(ArchiveError, "text budget"):
                read_objects(labels(), "label")


if __name__ == "__main__":
    unittest.main()
