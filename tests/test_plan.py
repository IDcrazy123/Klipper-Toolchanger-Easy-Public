import json
import hashlib
import io
import contextlib
import tempfile
import unittest
from pathlib import Path

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
