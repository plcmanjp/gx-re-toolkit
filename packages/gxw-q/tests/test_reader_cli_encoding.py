"""Read-only CLI encoding and argument validation using synthetic bytes."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gxw_ladder_reader as reader
import gxw_reference_ir as reference

LD = bytes.fromhex("03 00 03 04 90 00 04")
END = bytes.fromhex("04 34 02 04")


def text_frame(raw, marker):
    length = len(raw) + 4
    return bytes((length, marker, (length + 1) // 2)) + raw + bytes((length,))


class ReaderCliEncodingTests(unittest.TestCase):
    def test_text_stdout_and_directory_csv_preserve_selected_text(self):
        for encoding, text in (("cp949", "설비 준비"), ("cp1252", "café"), ("auto", "설비 준비")):
            raw = text.encode("cp949" if encoding == "auto" else encoding)
            body = text_frame(raw, 0x80) + LD + text_frame(raw, 0x82) + END
            pous = {"MAIN": (0, body, 1)}
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "input.gxw"
                source.write_bytes(b"synthetic input")
                output = Path(temporary) / "csv"
                for mode in ([], ["--csv"], ["--csv", str(output)]):
                    stdout = io.StringIO()
                    with (mock.patch.object(reader, "load_all_substreams", return_value={}),
                          mock.patch.object(reader, "collect_pous", return_value=(pous, {"M0": "준비"}, None)),
                          mock.patch.object(reader, "project_info", return_value=("SYNTHETIC", "QCPU")),
                          contextlib.redirect_stdout(stdout)):
                        reader.main([str(source), *mode, "--text-encoding", encoding])
                    if output.exists():
                        rendered = (output / "MAIN.csv").read_text(encoding="utf-16")
                        self.assertIn("준비", (output / "COMMENT.csv").read_text(encoding="utf-16"))
                    else:
                        rendered = stdout.getvalue()
                    self.assertIn(text, rendered)
                self.assertEqual(b"synthetic input", source.read_bytes())

    def test_invalid_arguments_fail_before_input_read(self):
        for arguments in (("--text-encoding", "utf8"), ("--typo",),
                          ("--text-enc", "cp949"), ("unexpected-directory",)):
            with self.subTest(arguments=arguments), mock.patch.object(reader, "load_all_substreams") as load:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    reader.main(["missing.gxw", *arguments])
                self.assertEqual(2, caught.exception.code)
                load.assert_not_called()
        for arguments in (("--text-encoding", "utf8"), ("--typo",), ("--text-enc", "cp949")):
            with self.subTest(arguments=arguments), mock.patch.object(reference, "build") as build:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    reference.main(["missing.gxw", "--output", "new.json", *arguments])
                self.assertEqual(2, caught.exception.code)
                build.assert_not_called()

    def test_defaults_and_strict_failure_preserve_existing_output(self):
        body = text_frame("설비".encode("cp949"), 0x80) + LD + END
        default = reader.pou_rows(body)[0][0][1]
        self.assertEqual("설비".encode("cp949").decode("cp1252"), default)
        for encoding in ("cp1252", "cp949", "auto"):
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                reader.pou_rows(text_frame(b"\x81", 0x80) + LD + END, text_encoding=encoding)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "existing"
            target.mkdir()
            sentinel = target / "MAIN.csv"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(FileExistsError):
                reader.output_csv("synthetic.gxw", {"MAIN": (0, body, 1)}, {},
                                  outdir=str(target), text_encoding="cp949")
            self.assertEqual(b"preserve", sentinel.read_bytes())

    @unittest.skipUnless(__import__("os").name == "nt", "synthetic CFB creation uses Windows COM")
    def test_reference_cli_file_backed_literal_and_no_clobber(self):
        from test_single_command import project
        raw = "설비".encode("cp949")
        body = text_frame(raw, 0x80) + LD + text_frame(raw, 0x82) + END
        with tempfile.TemporaryDirectory() as temporary:
            source = project(Path(temporary), body)
            before = source.read_bytes()
            for encoding in ("cp949", "auto", "cp1252"):
                target = Path(temporary) / (encoding + ".json")
                decoded_rows = []
                original_rows = reader.pou_rows
                def capture(*args, **kwargs):
                    result = original_rows(*args, **kwargs)
                    decoded_rows.extend(result[0])
                    return result
                with (contextlib.redirect_stdout(io.StringIO()),
                      mock.patch.object(reader, "pou_rows", side_effect=capture)):
                    self.assertEqual(0, reference.main([str(source), "--output", str(target),
                                                       "--text-encoding", encoding]))
                report = json.loads(target.read_text(encoding="utf-8"))
                expected = "설비" if encoding != "cp1252" else raw.decode("cp1252")
                self.assertEqual(expected, decoded_rows[0][1])
                self.assertEqual(expected, decoded_rows[2][1])
                self.assertEqual("COMPLETE", report["analysis"]["state"])
                original_output = target.read_bytes()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(1, reference.main([str(source), "--output", str(target)]))
                self.assertEqual(original_output, target.read_bytes())
            self.assertEqual(before, source.read_bytes())


if __name__ == "__main__":
    unittest.main()
