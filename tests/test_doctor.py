import os
import tempfile
import unittest
from pathlib import Path

from ktc_manager.inspector import inspect, snapshot
from ktc_manager.model import parse_manifest_data


def one_entry(owner="vendor-managed", target="target.txt"):
    item = {"id": "one", "owner": owner, "target_root": "config", "target": target}
    if owner == "vendor-managed":
        item.update(source="source.txt", delivery="symlink")
    return parse_manifest_data({"schema_version": 1, "profile": "test", "entries": [item]})


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.klipper = self.root / "klipper"
        self.config = self.root / "config"
        self.repo.mkdir()
        self.klipper.mkdir()
        self.config.mkdir()
        (self.repo / "source.txt").write_text("source", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def run_one(self, manifest=None):
        return inspect(manifest or one_entry(), self.repo, self.klipper, self.config)[0]

    def test_missing_vendor_does_not_create_parent(self):
        result = self.run_one()
        self.assertEqual(result["code"], "VENDOR_MISSING")
        self.assertFalse((self.config / "target.txt").exists())
        self.assertFalse((self.config / "new").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_correct_wrong_and_broken_links(self):
        target = self.config / "target.txt"
        try:
            target.symlink_to(self.repo / "source.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        self.assertEqual(self.run_one()["code"], "VENDOR_OK")
        target.unlink()
        target.symlink_to(os.path.relpath(self.repo / "source.txt", self.config))
        self.assertEqual(self.run_one()["code"], "VENDOR_OK")
        target.unlink()
        target.symlink_to(self.repo / "other.txt")
        self.assertEqual(self.run_one()["code"], "VENDOR_BROKEN_LINK")
        target.unlink()
        (self.root / "outside.txt").write_text("outside", encoding="utf-8")
        target.symlink_to(self.root / "outside.txt")
        before = snapshot([target, self.root / "outside.txt"])
        self.assertEqual(self.run_one()["code"], "VENDOR_WRONG_LINK")
        self.assertEqual(before, snapshot([target, self.root / "outside.txt"]))

    def test_regular_collision_preserves_bytes(self):
        target = self.config / "target.txt"
        target.write_text("source", encoding="utf-8")
        before = snapshot([target])
        self.assertEqual(self.run_one()["code"], "VENDOR_COLLISION_FILE")
        self.assertEqual(before, snapshot([target]))

    def test_directory_collision(self):
        (self.config / "target.txt").mkdir()
        self.assertEqual(self.run_one()["code"], "VENDOR_COLLISION_DIRECTORY")

    def test_protected_present_and_missing(self):
        manifest = one_entry("user-managed", "protected.txt")
        self.assertEqual(self.run_one(manifest)["code"], "PROTECTED_MISSING")
        (self.config / "protected.txt").write_text("keep", encoding="utf-8")
        self.assertEqual(self.run_one(manifest)["code"], "PROTECTED_PRESENT")

    def test_source_missing_directory_and_symlink(self):
        (self.repo / "source.txt").unlink()
        self.assertEqual(self.run_one()["code"], "SOURCE_MISSING")
        (self.repo / "source.txt").mkdir()
        self.assertEqual(self.run_one()["code"], "SOURCE_NOT_FILE")
        (self.repo / "source.txt").rmdir()
        try:
            (self.repo / "source.txt").symlink_to(self.root / "source-outside.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        self.assertEqual(self.run_one()["code"], "SOURCE_NOT_FILE")

    @unittest.skipIf(os.name == "nt", "permission mode semantics differ on Windows")
    def test_parent_symlink_escape(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.config / "escaped").symlink_to(outside, target_is_directory=True)
        manifest = one_entry(target="escaped/target.txt")
        self.assertEqual(self.run_one(manifest)["code"], "TARGET_ESCAPE")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_dangling_parent_symlink_escape(self):
        parent = self.config / "dangling"
        try:
            parent.symlink_to(self.root / "missing-dir", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        self.assertEqual(self.run_one(one_entry(target="dangling/target.txt"))["code"], "TARGET_ESCAPE")

    @unittest.skipIf(os.name == "nt", "symlink loop capability differs on Windows")
    def test_symlink_loop_is_blocked(self):
        loop = self.config / "loop"
        try:
            loop.symlink_to(loop, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        self.assertEqual(self.run_one(one_entry(target="loop/target.txt"))["code"], "TARGET_ESCAPE")

    def test_root_unavailable_missing_and_file(self):
        missing = self.root / "missing-config"
        manifest = one_entry()
        self.assertEqual(inspect(manifest, self.repo, self.klipper, missing)[0]["code"], "TARGET_ROOT_UNAVAILABLE")
        file_root = self.root / "config-file"
        file_root.write_text("not a directory", encoding="utf-8")
        self.assertEqual(inspect(manifest, self.repo, self.klipper, file_root)[0]["code"], "TARGET_ROOT_UNAVAILABLE")

    @unittest.skipIf(os.name == "nt", "permission mode semantics differ on Windows")
    def test_permission_denied_requires_writable_parent(self):
        if os.geteuid() == 0:
            self.skipTest("effective root bypasses POSIX permission checks")
        self.config.chmod(0o500)
        try:
            self.assertEqual(self.run_one()["code"], "PERMISSION_DENIED")
        finally:
            self.config.chmod(0o700)

    def test_snapshot_unchanged_after_doctor(self):
        paths = [self.repo / "source.txt", self.config / "target.txt", self.config]
        before = snapshot(paths)
        inspect(one_entry(), self.repo, self.klipper, self.config)
        self.assertEqual(before, snapshot(paths))
