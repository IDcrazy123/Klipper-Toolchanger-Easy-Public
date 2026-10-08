import json
import hashlib
import io
import contextlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ktc_manager.cli import main
from ktc_manager.inspector import inspect, plan_actions, snapshot, summary
from ktc_manager.model import load_manifest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "ownership-v1.json"


class PlanTests(unittest.TestCase):
    def test_mapping(self):
        manifest = load_manifest(MANIFEST)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            klipper = root / "klipper"
            config = root / "config"
            repo.mkdir(); klipper.mkdir(); config.mkdir()
            for entry in manifest.entries:
                if entry.owner == "vendor-managed":
                    source = repo.joinpath(*entry.source.split("/"))
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("source", encoding="utf-8")
                    target_root = klipper if entry.target_root == "klipper" else config
                    target_root.joinpath(*entry.target.split("/")).parent.mkdir(parents=True, exist_ok=True)
            paths = [repo, klipper, config]
            before = snapshot(paths)
            actions = plan_actions(inspect(manifest, repo, klipper, config))
            self.assertEqual(before, snapshot(paths))
            self.assertEqual(sum(a["action"] == "WOULD_LINK" for a in actions), 15)
            self.assertEqual(sum(a["action"] == "PRESERVE_MISSING" for a in actions), 7)
            self.assertFalse(any(a["action"] == "BLOCKED" for a in actions))
            self.assertEqual(summary(actions, "action")["blockers"], 0)

    def test_all_entry_missing_and_protected_plan_do_not_stream_source_content(self):
        manifest_data = {"schema_version": 1, "profile": "read-boundary", "entries": [{
            "id": "vendor", "owner": "vendor-managed", "source": "source.txt",
            "target_root": "config", "target": "target.py", "delivery": "symlink"
        }]}
        protected_data = {"schema_version": 1, "profile": "read-boundary", "entries": [
            {"id": "protected-user", "owner": "user-managed",
             "target_root": "config", "target": "user.cfg"},
            {"id": "protected-machine", "owner": "machine-state",
             "target_root": "config", "target": "printer.cfg"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, klipper, config = root / "repo", root / "klipper", root / "config"
            repo.mkdir(); klipper.mkdir(); config.mkdir()
            (repo / "source.txt").write_bytes(b"source")
            cases = ((manifest_data, None, ["VENDOR_MISSING"], ["WOULD_LINK"], 0, ()),
                     (protected_data, None,
                      ["PROTECTED_MISSING", "PROTECTED_MISSING"],
                      ["PRESERVE_MISSING", "PRESERVE_MISSING"], 0, ()),
                     (protected_data, None,
                      ["PROTECTED_PRESENT", "PROTECTED_PRESENT"],
                      ["PRESERVE", "PRESERVE"], 0, ("user.cfg", "printer.cfg")),
                     (manifest_data, "unknown", ["UNKNOWN_ID"], ["BLOCKED"], 10, ()))
            manifest_path = root / "manifest.json"
            for data, entry_id, expected_codes, expected_actions, expected_exit, existing in cases:
                for target in existing:
                    (config / target).write_text("keep", encoding="utf-8")
                manifest_path.write_text(json.dumps(data), encoding="utf-8")
                args = ["plan", "--dry-run", "--manifest", str(manifest_path),
                        "--repo-root", str(repo), "--klipper-root", str(klipper),
                        "--config-root", str(config), "--format", "json"]
                if entry_id is not None:
                    args.extend(("--id", entry_id))
                stream = io.StringIO()
                with patch("ktc_manager.inspector._stream_file") as stream_file:
                    with contextlib.redirect_stdout(stream):
                        exit_code = main(args)
                self.assertEqual(exit_code, expected_exit)
                actions = json.loads(stream.getvalue())["actions"]
                self.assertEqual([action["code"] for action in actions], expected_codes)
                self.assertEqual([action["action"] for action in actions], expected_actions)
                stream_file.assert_not_called()
                for target in existing:
                    (config / target).unlink()

    def test_selected_protected_plan_does_not_stream_source_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, klipper, config = root / "repo", root / "klipper", root / "config"
            repo.mkdir(); klipper.mkdir(); config.mkdir()
            manifest_path = root / "manifest.json"
            for owner, target in (("user-managed", "user.cfg"),
                                  ("machine-state", "printer.cfg")):
                for present in (False, True):
                    target_path = config / target
                    if present:
                        target_path.write_text("keep", encoding="utf-8")
                    manifest_path.write_text(json.dumps({
                        "schema_version": 1, "profile": "read-boundary", "entries": [{
                            "id": "protected", "owner": owner,
                            "target_root": "config", "target": target
                        }]
                    }), encoding="utf-8")
                    output = io.StringIO()
                    with patch("ktc_manager.inspector._stream_file") as stream_file:
                        with contextlib.redirect_stdout(output):
                            exit_code = main([
                                "plan", "--dry-run", "--format", "json", "--id", "protected",
                                "--manifest", str(manifest_path), "--repo-root", str(repo),
                                "--klipper-root", str(klipper), "--config-root", str(config)])
                    action = json.loads(output.getvalue())["actions"][0]
                    self.assertEqual(exit_code, 0)
                    self.assertEqual(action["code"],
                                     "PROTECTED_PRESENT" if present else "PROTECTED_MISSING")
                    self.assertEqual(action["action"], "PRESERVE" if present else "PRESERVE_MISSING")
                    stream_file.assert_not_called()
                    if present:
                        target_path.unlink()

    def test_source_permission_errors_block_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, klipper, config = root / "repo", root / "klipper", root / "config"
            repo.mkdir(); klipper.mkdir(); config.mkdir()
            source = repo / "source.txt"
            source.write_text("source", encoding="utf-8")
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({
                "schema_version": 1, "profile": "test", "entries": [{
                    "id": "vendor", "owner": "vendor-managed", "source": "source.txt",
                    "target_root": "config", "target": "target.txt", "delivery": "symlink"
                }]
            }), encoding="utf-8")
            real_lstat, real_resolve = os.lstat, Path.resolve
            def is_source(path):
                try:
                    return os.path.samefile(path, source)
                except OSError:
                    return os.path.normcase(os.path.abspath(os.fspath(path))) == \
                        os.path.normcase(os.path.abspath(str(source)))
            def deny_lstat(path):
                if is_source(path):
                    raise PermissionError("denied")
                return real_lstat(path)
            def deny_source(path, *args, **kwargs):
                if is_source(path) and kwargs.get("strict"):
                    raise PermissionError("denied")
                return real_resolve(path, *args, **kwargs)

            for check in ("lstat", "resolve"):
                with self.subTest(check=check):
                    output = io.StringIO()
                    mocked_check = (patch("ktc_manager.inspector.os.lstat", side_effect=deny_lstat)
                                    if check == "lstat" else
                                    patch("ktc_manager.inspector.Path.resolve", autospec=True,
                                          side_effect=deny_source))
                    with mocked_check, contextlib.redirect_stdout(output):
                        exit_code = main([
                            "plan", "--dry-run", "--format", "json", "--manifest",
                            str(manifest_path), "--repo-root", str(repo),
                            "--klipper-root", str(klipper), "--config-root", str(config)])
                    action = json.loads(output.getvalue())["actions"][0]
                    self.assertEqual(exit_code, 10)
                    self.assertEqual((action["action"], action["code"]),
                                     ("BLOCKED", "SOURCE_UNREADABLE"))
                    self.assertFalse(any(key in action for key in
                                         ("source_sha256", "target_sha256", "content_relation")))

    def test_plan_requires_dry_run_and_rejects_apply(self):
        self.assertEqual(main(["plan"]), 64)
        self.assertEqual(main(["apply"]), 64)

    def test_missing_vendor_parent_is_explicit_blocker(self):
        manifest = {
            "schema_version": 1, "profile": "test", "entries": [{
                "id": "vendor", "owner": "vendor-managed", "source": "source.txt",
                "target_root": "config", "target": "missing/target.py", "delivery": "symlink"
            }]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, config, klipper = root / "repo", root / "config", root / "klipper"
            repo.mkdir(); config.mkdir(); klipper.mkdir()
            (repo / "source.txt").write_text("source", encoding="utf-8")
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            stream = __import__("io").StringIO()
            import contextlib
            with contextlib.redirect_stdout(stream):
                code = main(["plan", "--dry-run", "--format", "json", "--manifest", str(path),
                             "--repo-root", str(repo), "--config-root", str(config),
                             "--klipper-root", str(klipper)])
            document = json.loads(stream.getvalue())
            self.assertEqual(code, 10)
            self.assertEqual(document["actions"][0]["action"], "BLOCKED")
            self.assertEqual(document["actions"][0]["code"], "TARGET_PARENT_MISSING")

    def test_selected_missing_source_digest_in_doctor_and_plan(self):
        source_bytes = b"selected source\r\nraw bytes"
        manifest_data = {"schema_version": 1, "profile": "selected-test", "entries": [{
            "id": "vendor", "owner": "vendor-managed", "source": "source.txt",
            "target_root": "config", "target": "tool/target.py", "delivery": "symlink"
        }]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, config, klipper = root / "repo", root / "config", root / "klipper"
            repo.mkdir(); config.mkdir(); klipper.mkdir()
            (repo / "source.txt").write_bytes(source_bytes)
            (config / "tool").mkdir()
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
            before = snapshot([repo, config, klipper])
            for command in (("doctor",), ("plan", "--dry-run")):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    code = main(list(command) + ["--id", "vendor", "--manifest", str(manifest_path),
                                                 "--repo-root", str(repo), "--config-root", str(config),
                                                 "--klipper-root", str(klipper), "--format", "json"])
                self.assertEqual(code, 0)
                document = json.loads(stream.getvalue())
                result = document["results"][0] if command[0] == "doctor" else document["actions"][0]
                self.assertEqual(result["code"], "VENDOR_MISSING")
                self.assertEqual(result["source_sha256"], hashlib.sha256(source_bytes).hexdigest())
                if command[0] == "plan":
                    self.assertEqual(result["action"], "WOULD_LINK")
            self.assertFalse((config / "tool/target.py").exists())
            self.assertEqual(before, snapshot([repo, config, klipper]))

    def test_collision_remains_blocked_with_fingerprints(self):
        manifest = {
            "schema_version": 1, "profile": "test", "entries": [{
                "id": "vendor", "owner": "vendor-managed", "source": "source.txt",
                "target_root": "config", "target": "target.py", "delivery": "symlink"
            }]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, config, klipper = root / "repo", root / "config", root / "klipper"
            repo.mkdir(); config.mkdir(); klipper.mkdir()
            (repo / "source.txt").write_bytes(b"source")
            (config / "target.py").write_bytes(b"target")
            parsed = __import__("ktc_manager.model", fromlist=["parse_manifest_data"]).parse_manifest_data(manifest)
            before = snapshot([repo, config, klipper])
            actions = plan_actions(inspect(parsed, repo, klipper, config, "vendor"))
            self.assertEqual(before, snapshot([repo, config, klipper]))
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0]["action"], "BLOCKED")
            self.assertEqual(actions[0]["content_relation"], "DIFFERENT")

    def test_json_is_parseable_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out1 = root / "one.txt"
            out2 = root / "two.txt"
            klipper = root / "klipper"
            config = root / "config"
            klipper.mkdir()
            config.mkdir()
            manifest = load_manifest(MANIFEST)
            for entry in manifest.entries:
                if entry.owner == "vendor-managed":
                    target_root = klipper if entry.target_root == "klipper" else config
                    target_root.joinpath(*entry.target.split("/")).parent.mkdir(parents=True, exist_ok=True)
            import contextlib
            import io
            for out in (out1, out2):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    self.assertEqual(main(["plan", "--dry-run", "--format", "json", "--repo-root", str(ROOT),
                                           "--klipper-root", str(klipper), "--config-root", str(config)]), 0)
                out.write_text(stream.getvalue(), encoding="utf-8")
            self.assertEqual(out1.read_text(), out2.read_text())
            self.assertEqual(json.loads(out1.read_text()), json.loads(out2.read_text()))
            self.assertNotIn("\x1b[", out1.read_text())
