import contextlib
import io
import json
import unittest

from ktc_manager.cli import main
from ktc_manager.cli import _text


class CliTests(unittest.TestCase):
    def test_help(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["--help"]), 0)
        self.assertIn("Read-only", stream.getvalue())

    def test_text_has_protocol_prefix(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["doctor", "--format", "text"])
        self.assertIn(code, (0, 10))
        self.assertTrue(stream.getvalue().startswith("KTCM1"))
        self.assertTrue(all(line.startswith("KTCM1 ") for line in stream.getvalue().splitlines()))
        self.assertIn('"id"', stream.getvalue())
        self.assertIn('"owner"', stream.getvalue())
        self.assertIn('"target"', stream.getvalue())

    def test_text_and_json_are_deterministic_without_ansi(self):
        text_values = []
        json_values = []
        for fmt in ("text", "json"):
            for _ in range(2):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    main(["doctor", "--format", fmt])
                value = stream.getvalue()
                self.assertNotIn("\x1b[", value)
                (text_values if fmt == "text" else json_values).append(value)
        self.assertEqual(text_values[0], text_values[1])
        self.assertEqual(json.loads(json_values[0]), json.loads(json_values[1]))

    def test_hostile_profile_is_json_quoted_on_one_protocol_line(self):
        document = {
            "profile": "profile with space\nand newline",
            "dry_run": True,
            "results": [{"id": "x", "owner": "vendor-managed", "code": "VENDOR_MISSING",
                         "target": "target name", "source": "source name"}],
            "summary": {"total": 1, "blockers": 0},
        }
        lines = _text(document, "doctor").splitlines()
        self.assertTrue(all(line.startswith("KTCM1 ") for line in lines))
        self.assertIn('profile="profile with space\\nand newline"', lines[0])

    def test_json_has_one_document(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["doctor", "--format", "json"])
        self.assertIn(code, (0, 10))
        self.assertIsInstance(json.loads(stream.getvalue()), dict)

    def test_json_unexpected_error_is_one_document_and_text_error_is_stderr(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["doctor", "--format", "json", "--manifest", "missing.json"])
        self.assertEqual(code, 65)
        self.assertIsInstance(json.loads(stream.getvalue()), dict)
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(["doctor", "--format", "text", "--manifest", "missing.json"]), 65)
        self.assertEqual(out.getvalue(), "")
        self.assertTrue(err.getvalue().startswith("KTCM1 error"))
