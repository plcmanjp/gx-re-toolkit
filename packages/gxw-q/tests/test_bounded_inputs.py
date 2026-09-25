"""GXW input limits are tested without proprietary OLE projects."""

import io
import unittest
from unittest.mock import patch

from gxw_bounded_ole import all_streams, stream
from gxw_bounded_xml import parse_xml
import wt9_fill_pou_body as encoder


class FakeOle:
    def __init__(self, entries):
        self.entries = entries

    def listdir(self, streams=True):
        return [[name] for name in self.entries]

    def get_size(self, name):
        return self.entries[name[-1] if isinstance(name, list) else name][0]

    def openstream(self, name):
        return io.BytesIO(self.entries[name[-1] if isinstance(name, list) else name][1])

    def close(self):
        pass


class BoundedInputTests(unittest.TestCase):
    def test_declared_and_actual_lengths_must_agree(self):
        self.assertEqual(stream(FakeOle({"12": (3, b"abc")}), "12"), b"abc")
        for declared, actual in ((2, b"abc"), (4, b"abc"), (257 * 1024 * 1024, b"")):
            with self.subTest(declared=declared), self.assertRaises(ValueError):
                stream(FakeOle({"12": (declared, actual)}), "12")

    def test_count_and_aggregate_preflight(self):
        self.assertEqual(all_streams(FakeOle({"12": (3, b"abc")})), {"12": b"abc"})
        with self.assertRaisesRegex(ValueError, "count"):
            all_streams(FakeOle({str(index): (0, b"") for index in range(10001)}))
        with self.assertRaisesRegex(ValueError, "aggregate"):
            all_streams(FakeOle({str(index): (256 * 1024 * 1024, b"") for index in range(3)}))

    def test_ole_path_alias_is_rejected_before_read(self):
        class Aliased(FakeOle):
            def listdir(self, streams=True):
                return [["a", "b"], ["a/b"]]
        with self.assertRaisesRegex(ValueError, "unsafe segment"):
            all_streams(Aliased({"a/b": (0, b"")}))

    def test_project_xml_entity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "DTD"):
            parse_xml(b'<!DOCTYPE R [<!ENTITY x "y">]><R>&x;</R>')

    def test_encoder_xml_paths_use_bounded_reads(self):
        with patch.object(encoder.bounded_ole, "open_file", return_value=FakeOle({
            "projectdatalist.xml": (4, b"<R/>"),
        })):
            self.assertEqual(encoder._read_xml_stream("synthetic.gxw", "projectdatalist.xml"), "<R/>")
        with patch.object(encoder.bounded_ole, "open_file", return_value=FakeOle({
            "history.xml": (2, b"<R/>"),
        })):
            with self.assertRaises(ValueError):
                encoder._history_with_stream_digests("synthetic.gxw", {})


if __name__ == "__main__":
    unittest.main()
