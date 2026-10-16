"""Generated binary fixtures only; no engineering-software or private corpus."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from gx3_r_parser_toolkit import parser, pou_details
from gx3_r_parser_toolkit.archive import ArchiveError


def synthetic_qpg(name="DemoPou", *, named=True, opaque_name=None):
    """Generate a directory from numeric layout rules and invented payloads."""
    prefix = bytearray(512)
    struct.pack_into("<I", prefix, 0, 0x02040080)
    for offset, size, tag in ((4, 12, 1), (16, 4, 0x102), (20, 8, 3), (28, 68, 4),
                              (96, 72, 0x205), (168, 36, 6), (204, 308, 7)):
        struct.pack_into("<HH", prefix, offset, size, tag)
    if named:
        encoded = name.encode("utf-16le") + bytes(2)
        name_field = struct.pack("<H", len(encoded)) + encoded + bytes(32) + struct.pack("<H", 0x100)
        opaque = bytearray((index * 7 + 3) % 256 for index in range(160))
        if opaque_name:
            decoy = opaque_name.encode("utf-16le") + bytes(2)
            opaque[20:20 + len(decoy)] = decoy
        tags = (0, 1, 3, 5, 6, 8, 0x10000, 0x10002, 0x10004, 0x10006, 0x10007)
        values = (bytes(4), struct.pack("<Q", 17), bytes(8), b"", b"", bytes(12),
                  bytes(32), bytes(opaque), bytes(184), name_field, bytes(236))
        counts = (6, 5)
    else:
        tags = (0, 1, 3, 4, 5, 6, 7, 0x10000, 0x10002, 0x10006, 0x10007)
        values = (bytes(4), struct.pack("<Q", 23), bytes(8), bytes(12), b"", b"", bytes(8),
                  bytes(72), bytes(88), b"", bytes(236))
        counts = (7, 4)
    directory, payload = [], bytearray()
    offset = 8 + len(tags) * 12
    for tag, value in zip(tags, values):
        directory.append((tag, offset if value else 0, len(value)))
        payload.extend(value)
        offset += len(value)
    mirror = struct.pack("<Q", 29)
    # The length includes its own u32, counts, directory, payload and mirror.
    length = 8 + len(tags) * 12 + len(payload) + len(mirror)
    extended = struct.pack("<IHH", length, *counts)
    extended += b"".join(struct.pack("<III", *entry) for entry in directory)
    extended += payload + mirror
    separator = struct.pack("<II", 0x2FD00000, 0)
    # Tail bytes and their count stay opaque to the supplemental reader.
    tail = mirror + struct.pack("<I", 2) + b"synthetic-tail"
    root_tail = len(prefix) + 4 + len(extended) + len(separator)
    result = prefix + struct.pack("<I", 0xFFFFFFFF) + extended + separator + tail
    struct.pack_into("<II", result, 8, root_tail, len(result))
    return bytes(result)


def change_u32(data, offset, value):
    copy = bytearray(data)
    struct.pack_into("<I", copy, offset, value)
    return bytes(copy)


def directory_position(data, tag):
    count = sum(struct.unpack_from("<HH", data, 520))
    for ordinal in range(count):
        at = 524 + ordinal * 12
        if struct.unpack_from("<I", data, at)[0] == tag:
            return at
    raise AssertionError("synthetic directory tag missing")


def field_position(data, tag):
    return 516 + struct.unpack_from("<I", data, directory_position(data, tag) + 4)[0]


class PouDetailsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "synthetic-pou.gx3"

    def write(self, entries=None, *, cpu="R04"):
        config = '<Root><Config Unit="' + cpu + '" UnitId="4097"/></Root>'
        if entries is None:
            entries = {"ConvertData/10/Program.qpg": synthetic_qpg(),
                       "ConvertData/10/PouLinkOrder.info": b"7\n"}
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("Config.xml", config)
            archive.writestr("!!Config.xml", config)
            for name, value in entries.items():
                archive.writestr(name, value)
        return self.source

    def read(self, entries=None, **options):
        return pou_details.parse_pou_details(self.write(entries, **options))

    def unknown_layout(self, data):
        result = self.read({"ConvertData/10/Program.qpg": data,
                            "ConvertData/10/PouLinkOrder.info": b"7\n"})
        self.assertEqual({"total": 1, "partial": 0, "unknown": 1}, result["counts"])
        record = result["records"][0]
        self.assertEqual("UNKNOWN", record["layout_status"])
        self.assertEqual({"status": "UNKNOWN", "value": None}, record["observed_name"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), record["source_digest"])
        self.assertTrue(any(finding["code"] == "UNKNOWN_LAYOUT" for finding in record["findings"]))

    def test_named_singleton_observation_is_deterministic_and_separate_from_ir(self):
        source = self.write()
        before = source.read_bytes()
        neutral = parser.parse(source)
        result = pou_details.parse_pou_details(source)
        self.assertEqual(result, pou_details.parse_pou_details(source))
        self.assertEqual(neutral, parser.parse(source))
        self.assertEqual(before, source.read_bytes())
        self.assertEqual(hashlib.sha256(before).hexdigest(), result["input"]["sha256"])
        self.assertEqual("plcman.gx3.r-pou-details", result["schema_name"])
        self.assertFalse(result["project_complete"])
        self.assertEqual({"total": 1, "partial": 1, "unknown": 0}, result["counts"])
        record = result["records"][0]
        self.assertEqual({"status": "OBSERVED", "value": "DemoPou"}, record["observed_name"])
        self.assertEqual("PRESENT", record["name_field_state"])
        self.assertEqual({"status": "UNKNOWN", "value": None}, record["semantic_owner"])
        self.assertEqual({"status": "UNKNOWN", "pou_id": None}, record["pou_binding"])
        self.assertEqual([6, 5], record["root_framing"]["directory_counts"])
        self.assertEqual(11, len(record["directory"]))
        self.assertEqual("SINGLETON", result["link_inventory"][0]["status"])
        json.dumps(result, allow_nan=False)

    def test_unnamed_unlinked_directory_is_explicitly_preserved(self):
        result = self.read({"ConvertData/10/Program.qpg": synthetic_qpg(),
                            "ConvertData/10/PouLinkOrder.info": b"7\n",
                            "ConvertData/20/Program.qpg": synthetic_qpg(named=False)})
        self.assertEqual({"total": 2, "partial": 2, "unknown": 0}, result["counts"])
        record = result["records"][1]
        self.assertEqual([7, 4], record["root_framing"]["directory_counts"])
        self.assertEqual("ZERO_LENGTH", record["name_field_state"])
        self.assertEqual({"status": "UNKNOWN", "value": None}, record["observed_name"])
        self.assertIsNone(record["link_inventory_index"])
        self.assertTrue(any(finding["code"] == "UNLINKED_CARRIER" for finding in record["findings"]))

    def test_name_scanning_decoys_are_ignored(self):
        result = self.read({"ConvertData/10/Program.qpg": synthetic_qpg(opaque_name="DecoyAB"),
                            "ConvertData/10/PouLinkOrder.info": b"7\n"})
        self.assertEqual("DemoPou", result["records"][0]["observed_name"]["value"])
        self.assertNotIn("DecoyAB", json.dumps(result))

    def test_unicode_name_is_strictly_decoded_from_the_indexed_field(self):
        result = self.read({"ConvertData/10/Program.qpg": synthetic_qpg("Example_\u03b1"),
                            "ConvertData/10/PouLinkOrder.info": b"7\n"})
        self.assertEqual("Example_\u03b1", result["records"][0]["observed_name"]["value"])

    def test_root_and_short_field_length_marker_and_mirror_fail_closed(self):
        data = synthetic_qpg()
        root_tail = struct.unpack_from("<I", data, 8)[0]
        extended_end = root_tail - 8
        cases = [data[:100], data[:-1], change_u32(data, 0, 0),
                 change_u32(data, 4, 0), change_u32(data, 8, root_tail - 1),
                 change_u32(data, 12, len(data) + 1), change_u32(data, 512, 0),
                 change_u32(data, 516, len(data)), change_u32(data, extended_end, 0),
                 change_u32(data, extended_end - 8, 0)]
        for value in cases:
            with self.subTest(sha=hashlib.sha256(value).hexdigest()):
                self.unknown_layout(value)

    def test_directory_counts_tags_gaps_overlaps_and_partial_zero_ranges(self):
        data = synthetic_qpg()
        at = directory_position(data, 1)
        offset = struct.unpack_from("<I", data, at + 4)[0]
        cases = [change_u32(data, 520, 0), change_u32(data, 520, 0xFFFFFFFF),
                 change_u32(data, at, 0), change_u32(data, at, 999),
                 change_u32(data, at + 4, offset + 1), change_u32(data, at + 4, offset - 1),
                 change_u32(data, at + 4, 0), change_u32(data, at + 8, 0xFFFFFFFF),
                 change_u32(data, directory_position(data, 0x10007) + 8, 235)]
        for value in cases:
            with self.subTest(sha=hashlib.sha256(value).hexdigest()):
                self.unknown_layout(value)

    def test_name_length_utf16_terminator_padding_and_identifier_reject_ambiguity(self):
        data = synthetic_qpg()
        at = field_position(data, pou_details.NAME_TAG)
        length = struct.unpack_from("<H", data, at)[0]
        mutations = []
        for position, payload in ((at, struct.pack("<H", 3)), (at, struct.pack("<H", 128)),
                                   (at + 2, struct.pack("<H", 0xD800)),
                                   (at + 2, struct.pack("<H", ord('/'))),
                                   (at + length, struct.pack("<H", ord('X'))),
                                   (at + 2 + length, b"x"), (at + length + 34, bytes(2))):
            changed = bytearray(data); changed[position:position + len(payload)] = payload
            mutations.append(bytes(changed))
        for value in mutations:
            with self.subTest(sha=hashlib.sha256(value).hexdigest()):
                self.unknown_layout(value)

    def test_missing_multi_invalid_and_duplicate_links_withhold_names(self):
        for links in (None, b"7\n8\n", b"7\n7\n", b" 7\n", b"\xff", b""):
            entries = {"ConvertData/10/Program.qpg": synthetic_qpg()}
            if links is not None:
                entries["ConvertData/10/PouLinkOrder.info"] = links
            with self.subTest(links=links):
                record = self.read(entries)["records"][0]
                self.assertEqual("OBSERVED_FORM", record["layout_status"])
                self.assertEqual({"status": "UNKNOWN", "value": None}, record["observed_name"])
        entries = {"ConvertData/10/Program.qpg": synthetic_qpg(),
                   "ConvertData/10/PouLinkOrder.info": b"7\n",
                   "ConvertData/20/Program.qpg": synthetic_qpg("OtherAA"),
                   "ConvertData/20/PouLinkOrder.info": b"7\n"}
        result = self.read(entries)
        self.assertTrue(all(item["status"] == "AMBIGUOUS" for item in result["link_inventory"]))
        self.assertTrue(all(record["observed_name"]["value"] is None for record in result["records"]))

    def test_all_qpg_names_and_unmatched_links_remain_in_census(self):
        result = self.read({"ConvertData/10/Program.qpg": synthetic_qpg(),
                            "ConvertData/10/PouLinkOrder.info": b"7\n",
                            "ConvertData/10/Extra.QPG": synthetic_qpg(),
                            "Other/Unknown.qpg": b"unobserved generated bytes",
                            "ConvertData/30/PouLinkOrder.info": b"9\n"})
        self.assertEqual(3, result["counts"]["total"])
        self.assertEqual(2, result["counts"]["unknown"])
        self.assertEqual([record["source_entry"] for record in result["records"]],
                         sorted(record["source_entry"] for record in result["records"]))
        named = next(record for record in result["records"] if record["name_field_state"] == "PRESENT")
        self.assertIsNone(named["observed_name"]["value"])
        self.assertTrue(any(finding["code"] == "UNMATCHED_LINK" for finding in result["findings"]))
        empty = self.read({})
        self.assertEqual({"total": 0, "partial": 0, "unknown": 0}, empty["counts"])
        self.assertEqual("UNKNOWN", empty["status"])

    def test_actual_parser_gates_and_same_file_digest_checks(self):
        with self.assertRaises(ArchiveError):
            self.read(cpu="Other")
        self.source.write_bytes(b"invalid synthetic archive")
        with self.assertRaises(ArchiveError):
            pou_details.parse_pou_details(self.source)
        source = self.write()
        original = parser.parse
        def changed_digest(path):
            value = original(path); value["input"]["sha256"] = "0" * 64; return value
        with patch.object(parser, "parse", side_effect=changed_digest):
            with self.assertRaisesRegex(ArchiveError, "between"):
                pou_details.parse_pou_details(source)
        with patch.object(pou_details, "sha256_file", return_value="0" * 64):
            with self.assertRaisesRegex(ArchiveError, "during"):
                pou_details.parse_pou_details(source)

    def test_carrier_link_output_and_aggregate_budgets_do_not_truncate(self):
        for key, limit, message in (("MAX_CARRIERS", 0, "census budget"),
                                    ("MAX_QPG_BYTES", 100, "carrier byte budget"),
                                    ("MAX_TOTAL_QPG_BYTES", 100, "aggregate byte budget"),
                                    ("MAX_LINK_BYTES", 1, "link text budget"),
                                    ("MAX_OUTPUT_TEXT", 10, "output text budget")):
            source = self.write()
            with self.subTest(key=key), patch.object(pou_details, key, limit):
                with self.assertRaisesRegex(ArchiveError, message):
                    pou_details.parse_pou_details(source)
        data = synthetic_qpg()
        tail = struct.unpack_from("<I", data, 8)[0]
        self.unknown_layout(change_u32(data, tail + 8, 0xFFFFFFFF))
        with patch.object(pou_details, "MAX_DIRECTORY_ENTRIES", 1):
            self.unknown_layout(data)


if __name__ == "__main__":
    unittest.main()
