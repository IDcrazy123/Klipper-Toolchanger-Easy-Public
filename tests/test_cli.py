import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ktc_manager.cli import main
from ktc_manager.cli import _text


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "manifests" / "ownership-v1.json"
TAP_MANIFEST = ROOT / "manifests" / "ownership-v1-tap-per-tool.json"


def manifest_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


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
        document = json.loads(stream.getvalue())
        self.assertIsInstance(document, dict)
        self.assertRegex(document["manifest_sha256"], r"^[0-9a-f]{64}$")

    def test_doctor_plan_digest_matches_selected_manifest_and_text_header(self):
        expected = manifest_digest(DEFAULT_MANIFEST)
        for command in (("doctor",), ("plan", "--dry-run")):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(list(command) + ["--profile", "cartographer", "--format", "json"])
            self.assertIn(code, (0, 10))
            self.assertEqual(json.loads(stream.getvalue())["manifest_sha256"], expected)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            main(["doctor", "--profile", "cartographer", "--format", "text"])
        self.assertIn("manifest_sha256=%s" % expected, stream.getvalue().splitlines()[0])

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

    def test_optional_selector_unknown_and_duplicate_boundaries(self):
        for command in ("doctor", "plan"):
            base = [command] + (["--dry-run"] if command == "plan" else [])
            for output_format in ("text", "json"):
                manifest = str(Path(__file__).resolve().parents[1] / "manifests" / "ownership-v1.json")
                stream = io.StringIO()
                error = io.StringIO()
                with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(error):
                    code = main(base + ["--id", "missing", "--repo-root", "missing-repo",
                                        "--manifest", manifest,
                                        "--config-root", "missing-config", "--klipper-root", "missing-klipper",
                                        "--format", output_format])
                self.assertEqual(code, 10)
                self.assertNotIn("usage:", stream.getvalue().lower() + error.getvalue().lower())
                if output_format == "json":
                    self.assertEqual(error.getvalue(), "")
                    document = json.loads(stream.getvalue())
                    key = "results" if command == "doctor" else "actions"
                    self.assertEqual(document[key][0]["code"], "UNKNOWN_ID")
                    self.assertEqual(document[key][0]["target"], "")
                else:
                    self.assertEqual(stream.getvalue().count("KTCM1 item"), 1)
                    self.assertIn('"code":"UNKNOWN_ID"', stream.getvalue())
                stream = io.StringIO()
                error = io.StringIO()
                with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(error):
                    code = main(base + ["--id", "one", "--id", "one", "--format", output_format])
                self.assertEqual(code, 64)
                self.assertNotIn("usage:", stream.getvalue().lower() + error.getvalue().lower())

    def test_profile_aliases_select_manifests_for_doctor_and_plan(self):
        with tempfile.TemporaryDirectory(prefix="repo space Ω ") as directory:
            repo = Path(directory)
            manifests = repo / "manifests"
            manifests.mkdir()
            (manifests / DEFAULT_MANIFEST.name).write_text(DEFAULT_MANIFEST.read_text(encoding="utf-8"),
                                                            encoding="utf-8")
            (manifests / TAP_MANIFEST.name).write_text(TAP_MANIFEST.read_text(encoding="utf-8"),
                                                       encoding="utf-8")
            for alias, profile in (("cartographer", "voron-5-tool-cartographer"),
                                   ("tap-per-tool", "voron-5-tool-tap-per-tool")):
                for command in (("doctor",), ("plan", "--dry-run")):
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream):
                        code = main(list(command) + ["--profile", alias, "--id", "missing",
                                                     "--repo-root", str(repo), "--format", "json"])
                    self.assertEqual(code, 10)
                    document = json.loads(stream.getvalue())
                    self.assertEqual(document["profile"], profile)
                    key = "results" if command[0] == "doctor" else "actions"
                    self.assertEqual(document[key][0]["code"], "UNKNOWN_ID")

    def test_no_profile_keeps_default_and_custom_manifest_remains_supported(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["doctor", "--id", "missing", "--repo-root", str(ROOT), "--format", "json"])
        self.assertEqual(code, 10)
        self.assertEqual(json.loads(stream.getvalue())["profile"], "voron-5-tool-cartographer")

        with tempfile.TemporaryDirectory() as directory:
            custom = Path(directory) / "custom.json"
            custom.write_text(json.dumps({"schema_version": 1, "profile": "custom-profile",
                                          "entries": []}), encoding="utf-8")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["doctor", "--manifest", str(custom), "--id", "missing",
                             "--format", "json"])
            self.assertEqual(code, 10)
            self.assertEqual(json.loads(stream.getvalue())["profile"], "custom-profile")

    def test_empty_explicit_manifest_does_not_select_default(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["doctor", "--manifest", "", "--repo-root", str(ROOT),
                         "--id", "missing", "--format", "json"])
        self.assertEqual(code, 65)
        self.assertIn("error", json.loads(stream.getvalue()))

    def test_profile_selector_usage_errors_are_deterministic_before_load(self):
        cases = (
            (["doctor", "--profile", "unknown"], "unknown --profile alias"),
            (["doctor", "--profile", "cartographer", "--profile", "tap-per-tool"],
             "doctor accepts at most one --profile"),
            (["doctor", "--profile", "cartographer", "--manifest", "missing.json"],
             "--profile and --manifest are mutually exclusive"),
        )
        for output_format in ("text", "json"):
            for args, message in cases:
                stream = io.StringIO()
                error = io.StringIO()
                with patch("ktc_manager.cli.load_manifest_with_digest") as load, \
                     patch("ktc_manager.cli.inspect") as inspect, \
                     contextlib.redirect_stdout(stream), contextlib.redirect_stderr(error):
                    code = main(args + ["--format", output_format])
                self.assertEqual(code, 64)
                load.assert_not_called()
                inspect.assert_not_called()
                self.assertNotIn("usage:", stream.getvalue().lower() + error.getvalue().lower())
                if output_format == "json":
                    self.assertEqual(json.loads(stream.getvalue())["error"], message)
                    self.assertEqual(error.getvalue(), "")
                else:
                    self.assertEqual(stream.getvalue(), "")
                    self.assertEqual(error.getvalue(), "KTCM1 error %s\n" % message)

    def test_alias_manifest_profile_mismatch_is_exit_65_before_inspection(self):
        for output_format in ("text", "json"):
            stream = io.StringIO()
            error = io.StringIO()
            with patch("ktc_manager.cli.load_manifest_with_digest",
                       return_value=(SimpleNamespace(profile="wrong-profile"), "0" * 64)) as load, \
                 patch("ktc_manager.cli.inspect") as inspect, \
                 contextlib.redirect_stdout(stream), contextlib.redirect_stderr(error):
                code = main(["doctor", "--profile", "cartographer", "--format", output_format])
            self.assertEqual(code, 65)
            load.assert_called_once()
            inspect.assert_not_called()
            self.assertNotIn("wrong-profile", stream.getvalue() + error.getvalue())
            if output_format == "json":
                self.assertEqual(json.loads(stream.getvalue())["error"],
                                 "manifest profile does not match --profile")
            else:
                self.assertEqual(error.getvalue(),
                                 "KTCM1 error manifest profile does not match --profile\n")

    def test_tap_alias_with_expected_profile_reaches_apply(self):
        document = {"schema_version": 1, "command": "apply",
                    "profile": "voron-5-tool-tap-per-tool", "dry_run": False,
                    "result": "NOOP", "actions": [],
                    "summary": {"total": 0, "blockers": 0}}
        stream = io.StringIO()
        with patch("ktc_manager.cli.apply_entry", return_value=(document, 0)) as apply, \
             contextlib.redirect_stdout(stream):
            code = main(["apply", "--profile", "tap-per-tool", "--id", "missing",
                         "--expect-profile", "voron-5-tool-tap-per-tool",
                         "--expect-manifest-sha256", manifest_digest(TAP_MANIFEST),
                         "--repo-root", str(ROOT), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["profile"], "voron-5-tool-tap-per-tool")
        self.assertEqual(apply.call_args.args[0].profile, "voron-5-tool-tap-per-tool")

    def test_profile_alias_and_expected_profile_mismatch_is_exit_65(self):
        for alias, expected in (("cartographer", "voron-5-tool-tap-per-tool"),
                                ("tap-per-tool", "voron-5-tool-cartographer")):
            with patch("ktc_manager.cli.apply_entry") as apply:
                code = main(["apply", "--profile", alias, "--id", "missing",
                             "--expect-profile", expected, "--repo-root", str(ROOT),
                             "--expect-manifest-sha256",
                             manifest_digest(DEFAULT_MANIFEST if alias == "cartographer" else TAP_MANIFEST),
                             "--format", "json"])
            self.assertEqual(code, 65)
            apply.assert_not_called()

    def test_profile_does_not_remove_apply_expected_profile_requirement(self):
        stream = io.StringIO()
        error = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(error):
            code = main(["apply", "--profile", "cartographer", "--id", "missing",
                         "--repo-root", str(ROOT), "--format", "text"])
        self.assertEqual(code, 64)
        self.assertEqual(error.getvalue(), "KTCM1 error apply requires exactly one --expect-profile\n")
        self.assertEqual(stream.getvalue(), "")
