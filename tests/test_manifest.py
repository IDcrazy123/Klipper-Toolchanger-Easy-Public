import json
import tempfile
import unittest
from pathlib import Path

from ktc_manager.model import ManifestError, load_manifest, parse_manifest_data


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "ownership-v1.json"


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_production_manifest_counts(self):
        manifest = load_manifest(MANIFEST)
        self.assertEqual(manifest.schema_version, 1)
        self.assertEqual(manifest.profile, "voron-5-tool-cartographer")
        self.assertEqual(len(manifest.entries), 22)
        self.assertEqual(sum(e.owner == "vendor-managed" for e in manifest.entries), 15)
        self.assertEqual(sum(e.owner == "user-managed" for e in manifest.entries), 6)
        self.assertEqual(sum(e.owner == "machine-state" for e in manifest.entries), 1)

    def test_production_mapping(self):
        entries = load_manifest(MANIFEST).entries
        vendor = {(e.source, e.target_root, e.target) for e in entries if e.owner == "vendor-managed"}
        expected_vendor = {
            ("klipper/extras/" + name, "klipper", "klippy/extras/" + name)
            for name in ("bed_thermal_adjust.py", "manual_rail.py", "multi_fan.py", "rounded_path.py",
                         "tool.py", "tool_probe.py", "tool_probe_endstop.py", "toolchanger.py",
                         "tools_calibrate.py")
        }
        expected_vendor.update({
            ("examples/easy-additions/" + name, "config", "toolchanger/readonly-configs/" + name)
            for name in ("calibrate-offsets.cfg", "crash-detection.cfg", "homing.cfg",
                         "toolchanger-macros.cfg", "toolchanger.cfg")
        })
        expected_vendor.add(("examples/easy-additions/user-configs/toolchanger-include_scanner.cfg",
                             "config", "toolchanger/readonly-configs/toolchanger-include.cfg"))
        self.assertEqual(vendor, expected_vendor)
        protected = {(e.owner, e.target_root, e.target) for e in entries if e.owner != "vendor-managed"}
        self.assertEqual(protected, {
            ("user-managed", "config", "toolchanger/toolchanger-config.cfg"),
            ("user-managed", "config", "toolchanger/tools/T0.cfg"),
            ("user-managed", "config", "toolchanger/tools/T1.cfg"),
            ("user-managed", "config", "toolchanger/tools/T2.cfg"),
            ("user-managed", "config", "toolchanger/tools/T3.cfg"),
            ("user-managed", "config", "toolchanger/tools/T4.cfg"),
            ("machine-state", "config", "printer.cfg"),
        })

    def test_exact_schema_and_paths(self):
        for key in ("extra",):
            data = dict(self.data)
            data[key] = True
            with self.assertRaises(ManifestError):
                parse_manifest_data(data)
        for bad in ("/x", "C:/x", "a\\b", "a/../b", "a/*", ".", "./x", "a/./b", "a//b", "a/",
                    "foo/D:/bar", "foo/C:/bar", "foo/name:ads", "CON", "con.txt", "AUX.cfg",
                    "COM1.py", "Lpt9/file", "trailing.", "trailing ", "bad\x01name", "a<b", 'a>b',
                    'a"b', "a|b"):
            data = json.loads(json.dumps(self.data))
            data["entries"][0]["target"] = bad
            with self.assertRaises(ManifestError):
                parse_manifest_data(data)
        for bad in ("foo/D:/bar", "foo/C:/bar", "foo/name:ads", "CON", "con.txt", "AUX.cfg",
                    "COM1.py", "Lpt9/file", "trailing.", "trailing ", "bad\x01name", "a<b", 'a>b',
                    'a"b', "a|b"):
            data = json.loads(json.dumps(self.data))
            data["entries"][0]["source"] = bad
            with self.assertRaises(ManifestError):
                parse_manifest_data(data)
        valid = json.loads(json.dumps(self.data))
        valid["entries"][0]["target"] = "foo/bar"
        valid["entries"][0]["source"] = "foo/bar"
        self.assertEqual(parse_manifest_data(valid).entries[0].target, "foo/bar")

    def test_duplicate_id_and_casefold_target(self):
        data = json.loads(json.dumps(self.data))
        data["entries"][1]["id"] = data["entries"][0]["id"]
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)
        data = json.loads(json.dumps(self.data))
        data["entries"][1]["target"] = data["entries"][0]["target"].upper()
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)
        data = json.loads(json.dumps(self.data))
        data["entries"][1]["target_root"] = "config"
        data["entries"][1]["target"] = data["entries"][0]["target"]
        self.assertEqual(len(parse_manifest_data(data).entries), 22)

    def test_overlapping_target_ownership(self):
        data = {"schema_version": 1, "profile": "x", "entries": [
            {"id": "a", "owner": "user-managed", "target_root": "config", "target": "tools"},
            {"id": "b", "owner": "machine-state", "target_root": "config", "target": "tools/T0.cfg"},
        ]}
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)

    def test_owner_shapes(self):
        data = json.loads(json.dumps(self.data))
        data["entries"][0].pop("source")
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)
        for owner in ([], {}):
            data = json.loads(json.dumps(self.data))
            data["entries"][0]["owner"] = owner
            with self.assertRaises(ManifestError):
                parse_manifest_data(data)

    def test_schema_version_bool_rejected(self):
        data = json.loads(json.dumps(self.data))
        data["schema_version"] = True
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)

    def test_invalid_enum(self):
        data = json.loads(json.dumps(self.data))
        data["entries"][0]["delivery"] = "copy"
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)
        data = json.loads(json.dumps(self.data))
        data["entries"][0]["target_root"] = "other"
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)
        data = json.loads(json.dumps(self.data))
        data["entries"][15]["source"] = "unexpected"
        with self.assertRaises(ManifestError):
            parse_manifest_data(data)

    def test_paths_with_spaces_and_unicode_are_valid(self):
        data = {"schema_version": 1, "profile": "x", "entries": [{
            "id": "x", "owner": "user-managed", "target_root": "config", "target": "工具 dir/file name.cfg"
        }]}
        self.assertEqual(parse_manifest_data(data).entries[0].target, "工具 dir/file name.cfg")

    def test_manifest_file_can_be_loaded_from_temp_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "m.json"
            path.write_text(json.dumps(self.data), encoding="utf-8")
            self.assertEqual(len(load_manifest(path).entries), 22)
