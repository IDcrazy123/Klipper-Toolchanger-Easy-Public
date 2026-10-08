import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from ktc_manager.inspector import (_collision_fingerprints, canonical_root, inspect, snapshot)
from ktc_manager.model import parse_manifest_data


def one_entry(owner="vendor-managed", target="target.txt"):
    item = {"id": "one", "owner": owner, "target_root": "config", "target": target}
    if owner == "vendor-managed":
        item.update(source="source.txt", delivery="symlink")
    return parse_manifest_data({"schema_version": 1, "profile": "test", "entries": [item]})


def same_existing_path(path, expected):
    try:
        return os.path.samefile(str(path), str(expected))
    except OSError:
        return Path(path).resolve(strict=False) == Path(expected).resolve(strict=False)


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
        self.assertNotIn("source_sha256", result)
        self.assertFalse((self.config / "target.txt").exists())
        self.assertFalse((self.config / "new").exists())

    def test_selected_missing_vendor_includes_raw_source_digest_read_only(self):
        source_bytes = b"source\x00with\r\nbytes"
        (self.repo / "source.txt").write_bytes(source_bytes)
        before = snapshot([self.repo, self.klipper, self.config])
        result = inspect(one_entry(), self.repo, self.klipper, self.config, "one")[0]
        self.assertEqual(result["code"], "VENDOR_MISSING")
        self.assertEqual(result["source_sha256"], hashlib.sha256(source_bytes).hexdigest())
        self.assertFalse((self.config / "target.txt").exists())
        self.assertEqual(before, snapshot([self.repo, self.klipper, self.config]))

    def test_selected_missing_digest_fails_closed_on_read_failure_or_source_change(self):
        before = snapshot([self.repo, self.klipper, self.config])
        with patch("ktc_manager.inspector._stream_file",
                   return_value=("SOURCE_UNREADABLE", None)):
            unreadable = inspect(one_entry(), self.repo, self.klipper, self.config, "one")[0]
        self.assertEqual(unreadable["code"], "SOURCE_UNREADABLE")
        self.assertNotIn("source_sha256", unreadable)

        with patch("ktc_manager.inspector._stream_file",
                   return_value=(None, {"raw_sha256": "a" * 64, "state": ()})):
            changed = inspect(one_entry(), self.repo, self.klipper, self.config, "one")[0]
        self.assertEqual(changed["code"], "SOURCE_CHANGED")
        self.assertNotIn("source_sha256", changed)
        self.assertEqual(before, snapshot([self.repo, self.klipper, self.config]))

    def test_target_appearing_during_selected_missing_hash_is_blocked_without_digest(self):
        target = self.config / "target.txt"
        real_stream = __import__("ktc_manager.inspector", fromlist=["_stream_file"])._stream_file

        def create_target_during_hash(path, role):
            target.write_bytes(b"racer")
            return real_stream(path, role)

        with patch("ktc_manager.inspector._stream_file", side_effect=create_target_during_hash), \
             patch("ktc_manager.inspector._collision_fingerprints") as fingerprints:
            result = inspect(one_entry(), self.repo, self.klipper, self.config, "one")[0]
        self.assertEqual(result["code"], "TARGET_CHANGED")
        self.assertFalse(any(key in result for key in
                             ("source_sha256", "target_sha256", "content_relation")))
        fingerprints.assert_not_called()
        self.assertEqual(target.read_bytes(), b"racer")

    def test_selected_protected_entry_has_no_source_digest(self):
        result = inspect(one_entry("user-managed", "protected.cfg"),
                         self.repo, self.klipper, self.config, "one")[0]
        self.assertEqual(result["code"], "PROTECTED_MISSING")
        self.assertNotIn("source_sha256", result)

    def test_selected_entry_returns_one_fingerprinted_result_and_unknown_touches_no_roots(self):
        target = self.config / "target.txt"
        target.write_bytes(b"target")
        manifest = one_entry()
        result = inspect(manifest, self.repo, self.klipper, self.config, "one")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["code"], "VENDOR_COLLISION_FILE")
        self.assertIn("source_sha256", result[0])
        with patch("ktc_manager.inspector.canonical_root") as canonical:
            unknown = inspect(manifest, self.root / "bad-repo", self.root / "bad-klipper",
                              self.root / "bad-config", "ONE")
        canonical.assert_not_called()
        self.assertEqual(unknown, [{"id": "ONE", "owner": "", "code": "UNKNOWN_ID", "target": ""}])

    def test_selected_root_isolation(self):
        manifest = one_entry(target="tool/target.txt")
        (self.repo / "source.txt").write_bytes(b"source")
        (self.config / "tool").mkdir()
        poison_klipper = self.root / "missing-klipper"
        real_canonical_root = canonical_root
        def config_guard(path):
            if Path(path) == poison_klipper:
                raise AssertionError("inactive Klipper root was canonicalized")
            return real_canonical_root(path)
        with patch("ktc_manager.inspector.canonical_root", side_effect=config_guard):
            config_result = inspect(manifest, self.repo, poison_klipper,
                                    self.config, "one")[0]
        self.assertEqual(config_result["code"], "VENDOR_MISSING")
        klipper_manifest = parse_manifest_data({"schema_version": 1, "profile": "test", "entries": [{
            "id": "one", "owner": "vendor-managed", "source": "source.txt",
            "target_root": "klipper", "target": "tool/target.txt", "delivery": "symlink"
        }]})
        (self.klipper / "tool").mkdir()
        poison_config = self.root / "missing-config"
        def klipper_guard(path):
            if Path(path) == poison_config:
                raise AssertionError("inactive config root was canonicalized")
            return real_canonical_root(path)
        with patch("ktc_manager.inspector.canonical_root", side_effect=klipper_guard):
            klipper_result = inspect(klipper_manifest, self.repo, self.klipper,
                                     poison_config, "one")[0]
        self.assertEqual(klipper_result["code"], "VENDOR_MISSING")

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
        result = self.run_one()
        self.assertEqual(result["code"], "VENDOR_COLLISION_FILE")
        self.assertEqual(result["source_sha256"], hashlib.sha256(b"source").hexdigest())
        self.assertEqual(result["target_sha256"], hashlib.sha256(b"source").hexdigest())
        self.assertEqual(result["content_relation"], "IDENTICAL_BYTES")
        self.assertEqual(before, snapshot([target]))

    def test_collision_content_relations_are_raw_and_crlf_exact(self):
        target = self.config / "target.txt"
        cases = ((b"same\x00", b"same\x00", "IDENTICAL_BYTES"),
                 (b"line\r\nend", b"line\nend", "EQUAL_AFTER_CRLF_NORMALIZATION"),
                 (b"line\rend", b"line\nend", "DIFFERENT"),
                 (b"\xef\xbb\xbfline", b"line", "DIFFERENT"),
                 (b"line ", b"line", "DIFFERENT"),
                 (b"line\n", b"line", "DIFFERENT"))
        for source, target_bytes, relation in cases:
            (self.repo / "source.txt").write_bytes(source)
            target.write_bytes(target_bytes)
            result = self.run_one()
            self.assertEqual(result["code"], "VENDOR_COLLISION_FILE")
            self.assertEqual(result["content_relation"], relation)
            self.assertEqual(result["source_sha256"], hashlib.sha256(source).hexdigest())
            self.assertEqual(result["target_sha256"], hashlib.sha256(target_bytes).hexdigest())

    def test_crlf_split_at_stream_chunk_boundary(self):
        prefix = b"A" * (1024 * 1024 - 1)
        source = prefix + b"\r\nB"
        target = prefix + b"\nB"
        (self.repo / "source.txt").write_bytes(source)
        (self.config / "target.txt").write_bytes(target)
        result = self.run_one()
        self.assertEqual(result["content_relation"], "EQUAL_AFTER_CRLF_NORMALIZATION")
        self.assertEqual(result["source_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(result["target_sha256"], hashlib.sha256(target).hexdigest())

    def test_protected_entries_are_not_fingerprinted(self):
        manifest = one_entry("user-managed", "protected.txt")
        (self.config / "protected.txt").write_bytes(b"protected")
        with patch("ktc_manager.inspector._collision_fingerprints") as fingerprints:
            result = self.run_one(manifest)
        fingerprints.assert_not_called()
        self.assertEqual(result["code"], "PROTECTED_PRESENT")
        self.assertNotIn("source_sha256", result)
        self.assertNotIn("target_sha256", result)
        self.assertNotIn("content_relation", result)

    def test_fingerprint_read_failure_and_source_change_fail_closed(self):
        target = self.config / "target.txt"
        target.write_bytes(b"target")
        with patch("ktc_manager.inspector.os.open", side_effect=PermissionError("read denied")):
            result = self.run_one()
        self.assertEqual(result["code"], "SOURCE_UNREADABLE")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "FIFO/nonblocking capability unavailable")
    def test_fifo_swap_is_nonblocking_and_fail_closed(self):
        target = self.config / "target.txt"
        target.write_bytes(b"target")
        fifo = self.root / "fingerprint.fifo"
        os.mkfifo(str(fifo))
        real_open = os.open
        flags_seen = []
        def open_fifo(path, flags):
            flags_seen.append(flags)
            return real_open(str(fifo), flags)
        try:
            with patch("ktc_manager.inspector.os.open", side_effect=open_fifo):
                result = self.run_one()
        finally:
            fifo.unlink(missing_ok=True)
        self.assertTrue(flags_seen[0] & os.O_NONBLOCK)
        self.assertEqual(result["code"], "SOURCE_CHANGED")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))

    def test_containment_failures_are_blockers_without_fingerprints(self):
        repo = canonical_root(self.repo)
        config = canonical_root(self.config)
        source = repo / "source.txt"
        target = config / "target.txt"
        target.write_bytes(b"target")
        collision = {"code": "VENDOR_COLLISION_FILE", "source": str(source),
                     "target": str(target), "id": "one", "owner": "vendor-managed"}
        before = snapshot([self.root])
        with patch("ktc_manager.inspector.inspect_entry", return_value=collision), \
             patch("ktc_manager.inspector._source_state",
                   return_value=("SOURCE_ESCAPE", source)):
            result = inspect(one_entry(), self.repo, self.klipper, self.config)[0]
        self.assertEqual(result["code"], "SOURCE_ESCAPE")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))
        self.assertEqual(before, snapshot([self.root]))

        with patch("ktc_manager.inspector.inspect_entry", return_value=collision), \
             patch("ktc_manager.inspector._source_state",
                   side_effect=[(None, source), ("SOURCE_CHANGED", source)]), \
             patch("ktc_manager.inspector._stream_file",
                   return_value=(None, {"raw_sha256": "a", "normalized_sha256": "a", "state": ()})):
            result = inspect(one_entry(), self.repo, self.klipper, self.config)[0]
        self.assertEqual(result["code"], "SOURCE_CHANGED")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))

        with patch("ktc_manager.inspector.inspect_entry", return_value=collision), \
             patch("ktc_manager.inspector._source_state",
                   return_value=(None, source)), \
             patch("ktc_manager.inspector._parent_structure",
                   side_effect=[None, "TARGET_PARENT_CHANGED"]), \
             patch("ktc_manager.inspector._file_state", return_value=()), \
             patch("ktc_manager.inspector._stream_file",
                   return_value=(None, {"raw_sha256": "a", "normalized_sha256": "a",
                                       "raw_size": 1, "normalized_size": 1, "state": ()})):
            result = inspect(one_entry(), self.repo, self.klipper, self.config)[0]
        self.assertEqual(result["code"], "TARGET_PARENT_CHANGED")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))

    def test_fingerprint_read_failure_target_and_races_fail_closed(self):
        target = self.config / "target.txt"
        target.write_bytes(b"target")
        real_open = os.open
        def target_read_failure(path, flags):
            if os.path.samefile(str(path), str(target)):
                raise PermissionError("target read denied")
            return real_open(path, flags)
        with patch("ktc_manager.inspector.os.open", side_effect=target_read_failure):
            result = self.run_one()
        self.assertEqual(result["code"], "TARGET_UNREADABLE")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))
        real_lstat = os.lstat
        source = canonical_root(self.repo) / "source.txt"
        calls = []
        def changing_lstat(path):
            info = real_lstat(path)
            if same_existing_path(path, source):
                calls.append(1)
                if len(calls) >= 3:
                    values = list(info)
                    values[6] += 1
                    return os.stat_result(values)
            return info
        with patch("ktc_manager.inspector.os.lstat", side_effect=changing_lstat):
            result = self.run_one()
        self.assertEqual(result["code"], "SOURCE_CHANGED")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))
        target = canonical_root(self.config) / "target.txt"
        target_calls = []
        def changing_target_lstat(path):
            info = real_lstat(path)
            if same_existing_path(path, target):
                target_calls.append(1)
                if len(target_calls) >= 2:
                    values = list(info)
                    values[6] += 1
                    return os.stat_result(values)
            return info
        with patch("ktc_manager.inspector.os.lstat", side_effect=changing_target_lstat):
            result = self.run_one()
        self.assertEqual(result["code"], "TARGET_CHANGED")
        self.assertFalse(any(key in result for key in ("source_sha256", "target_sha256", "content_relation")))

    def test_doctor_json_and_text_collision_are_deterministic(self):
        (self.config / "target.txt").write_bytes(b"target")
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps({
            "schema_version": 1, "profile": "test", "entries": [{
                "id": "one", "owner": "vendor-managed", "source": "source.txt",
                "target_root": "config", "target": "target.txt", "delivery": "symlink"
            }]
        }), encoding="utf-8")
        values = []
        for output_format in ("json", "text"):
            for _ in range(2):
                stream = StringIO()
                with redirect_stdout(stream):
                    code = __import__("ktc_manager.cli", fromlist=["main"]).main(
                        ["doctor", "--format", output_format, "--repo-root", str(self.repo),
                         "--manifest", str(manifest_path),
                         "--config-root", str(self.config), "--klipper-root", str(self.klipper)])
                self.assertEqual(code, 10)
                values.append(stream.getvalue())
        self.assertEqual(values[0], values[1])
        self.assertEqual(values[2], values[3])
        self.assertNotIn("\x1b[", "".join(values))

    def test_directory_collision(self):
        (self.config / "target.txt").mkdir()
        self.assertEqual(self.run_one()["code"], "VENDOR_COLLISION_DIRECTORY")

    def test_protected_present_and_missing(self):
        manifest = one_entry("user-managed", "protected.txt")
        self.assertEqual(self.run_one(manifest)["code"], "PROTECTED_MISSING")
        (self.config / "protected.txt").write_text("keep", encoding="utf-8")
        self.assertEqual(self.run_one(manifest)["code"], "PROTECTED_PRESENT")

    def test_protected_root_unavailable(self):
        manifest = one_entry("machine-state", "printer.cfg")
        missing_root = self.root / "missing-config"
        self.assertEqual(inspect(manifest, self.repo, self.klipper, missing_root)[0]["code"],
                         "TARGET_ROOT_UNAVAILABLE")

    @unittest.skipIf(os.name == "nt", "permission mode semantics differ on Windows")
    def test_protected_unwritable_real_parent_is_still_present_or_missing(self):
        if os.geteuid() == 0:
            self.skipTest("effective root bypasses POSIX permission checks")
        parent = self.config / "protected"
        parent.mkdir()
        (parent / "printer.cfg").write_text("keep", encoding="utf-8")
        parent.chmod(0o500)
        try:
            missing = one_entry("user-managed", "protected/missing.cfg")
            present = one_entry("user-managed", "protected/printer.cfg")
            self.assertEqual(self.run_one(missing)["code"], "PROTECTED_MISSING")
            self.assertEqual(self.run_one(present)["code"], "PROTECTED_PRESENT")
        finally:
            parent.chmod(0o700)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_existing_vendor_under_parent_symlink_is_blocked(self):
        real_parent = self.config / "real"
        real_parent.mkdir()
        try:
            (self.config / "link").symlink_to(real_parent, target_is_directory=True)
            (real_parent / "target.txt").symlink_to(self.repo / "source.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        self.assertEqual(self.run_one(one_entry(target="link/target.txt"))["code"],
                         "TARGET_PARENT_SYMLINK")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_protected_parent_escape_is_blocked(self):
        outside = self.root / "outside"
        outside.mkdir()
        try:
            (self.config / "escape").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        protected = one_entry("machine-state", "escape/printer.cfg")
        self.assertEqual(self.run_one(protected)["code"], "TARGET_ESCAPE")

    @unittest.skipIf(os.name == "nt", "permission mode semantics differ on Windows")
    def test_correct_vendor_link_under_unwritable_real_parent_is_ok(self):
        if os.geteuid() == 0:
            self.skipTest("effective root bypasses POSIX permission checks")
        parent = self.config / "vendor"
        parent.mkdir()
        try:
            (parent / "target.txt").symlink_to(self.repo / "source.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        parent.chmod(0o500)
        try:
            self.assertEqual(self.run_one(one_entry(target="vendor/target.txt"))["code"], "VENDOR_OK")
        finally:
            parent.chmod(0o700)

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
