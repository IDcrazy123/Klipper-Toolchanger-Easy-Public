import errno
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ktc_manager.cli import main
from ktc_manager.executor import apply_entry
from ktc_manager.inspector import (_parent_structure, _source_state, canonical_root,
                                   inspect_entry, revalidate_source, snapshot)
from ktc_manager.model import ManifestError, parse_manifest_data


def manifest(owner="vendor-managed", source="source.txt", target="tool/target.py", ident="vendor",
             target_root="config"):
    entry = {"id": ident, "owner": owner, "target_root": target_root, "target": target}
    if owner == "vendor-managed":
        entry.update(source=source, delivery="symlink")
    return parse_manifest_data({"schema_version": 1, "profile": "apply-test", "entries": [entry]})


def same_existing_path(path, expected):
    try:
        return os.path.samefile(str(path), str(expected))
    except OSError:
        return Path(path).resolve(strict=False) == Path(expected).resolve(strict=False)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.config = self.root / "config"
        self.klipper = self.root / "klipper"
        self.repo.mkdir()
        self.config.mkdir()
        self.klipper.mkdir()
        (self.repo / "source.txt").write_text("source", encoding="utf-8")
        (self.config / "tool").mkdir()
        self.manifest = manifest()

    def tearDown(self):
        self.tmp.cleanup()

    def apply(self, current=None):
        return apply_entry(current or self.manifest, "vendor", self.repo, self.klipper, self.config)

    def blocked_unchanged(self, current, ident="vendor"):
        before = snapshot([self.root])
        document, code = apply_entry(current, ident, self.repo, self.klipper, self.config)
        self.assertEqual(before, snapshot([self.root]))
        return document, code

    def require_symlink(self):
        probe = self.config / "tool/probe.link"
        try:
            os.symlink(str(self.repo / "source.txt"), str(probe), target_is_directory=False)
        except OSError as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        finally:
            if probe.is_symlink():
                probe.unlink()

    def test_actual_create_and_rerun_noop(self):
        self.require_symlink()
        document, code = self.apply()
        self.assertEqual((document["result"], code), ("APPLIED", 0))
        target = self.config / "tool/target.py"
        self.assertTrue(target.is_symlink())
        self.assertEqual(target.resolve(), (self.repo / "source.txt").resolve())
        document, code = self.apply()
        self.assertEqual((document["result"], code), ("NOOP", 0))

    def test_file_dir_wrong_and_broken_collisions_preserved(self):
        target = self.config / "tool/target.py"
        for kind in ("file", "dir", "wrong", "broken"):
            if target.exists() or target.is_symlink():
                if target.is_dir() and not target.is_symlink():
                    target.rmdir()
                else:
                    target.unlink()
            if kind == "file":
                target.write_text("keep", encoding="utf-8")
            elif kind == "dir":
                target.mkdir()
            elif kind in ("wrong", "broken"):
                try:
                    target.symlink_to(self.root / ("other.txt" if kind == "wrong" else "missing.txt"))
                except OSError as exc:
                    self.skipTest("symlink unavailable: %s" % exc)
                if kind == "wrong":
                    (self.root / "other.txt").write_text("other", encoding="utf-8")
            before = snapshot([self.root])
            document, code = self.apply()
            self.assertEqual(code, 10)
            self.assertEqual(document["result"], "BLOCKED")
            self.assertEqual(before, snapshot([self.root]))

    def test_apply_collision_output_has_no_fingerprint_fields(self):
        target = self.config / "tool/target.py"
        target.write_bytes(b"target")
        with patch("ktc_manager.inspector._collision_fingerprints") as fingerprints:
            document, code = self.apply()
        fingerprints.assert_not_called()
        self.assertEqual((document["result"], code), ("BLOCKED", 10))
        self.assertEqual(set(document), {"schema_version", "command", "profile", "dry_run",
                                         "result", "summary", "actions"})
        self.assertEqual(document["summary"], {"total": 1, "blockers": 1, "created": 0, "noop": 0})
        action = document["actions"][0]
        self.assertEqual(set(action), {"id", "owner", "code", "action", "target", "source"})
        self.assertEqual(action["code"], "VENDOR_COLLISION_FILE")
        self.assertNotIn("source_sha256", action)
        self.assertNotIn("target_sha256", action)
        self.assertNotIn("content_relation", action)

    def test_protected_unknown_and_repeated_id_are_blocked(self):
        protected = manifest("user-managed", ident="protected", target="tool/user.cfg")
        (self.config / "tool/user.cfg").write_text("keep", encoding="utf-8")
        document, code = self.blocked_unchanged(protected, "protected")
        self.assertEqual((document["result"], code), ("BLOCKED", 10))
        machine = manifest("machine-state", ident="machine", target="tool/printer.cfg")
        document, code = self.blocked_unchanged(machine, "machine")
        self.assertEqual((document["result"], code), ("BLOCKED", 10))
        (self.config / "tool/printer.cfg").write_text("machine", encoding="utf-8")
        document, code = self.blocked_unchanged(machine, "machine")
        self.assertEqual((document["result"], code), ("BLOCKED", 10))
        unknown, code = self.blocked_unchanged(self.manifest, "missing")
        self.assertEqual((unknown["result"], code), ("BLOCKED", 10))
        mismatch, code = self.blocked_unchanged(self.manifest, "VENDOR")
        self.assertEqual((mismatch["result"], code), ("BLOCKED", 10))

    def test_unknown_id_skips_all_apply_path_access(self):
        before = snapshot([self.root])
        with patch("ktc_manager.executor.canonical_root") as canonical, \
             patch("ktc_manager.executor.inspect_entry") as inspect, \
             patch("ktc_manager.executor.revalidate_source") as revalidate, \
             patch("ktc_manager.executor.os.symlink") as symlink:
            document, code = apply_entry(self.manifest, "unknown", self.repo,
                                         self.klipper, self.config)
        self.assertEqual((document["actions"][0]["code"], document["result"], code),
                         ("UNKNOWN_ID", "BLOCKED", 10))
        self.assertEqual(document["actions"][0]["owner"], "")
        self.assertEqual(document["actions"][0]["target"], "")
        self.assertEqual(document["actions"][0]["source"], "")
        canonical.assert_not_called()
        inspect.assert_not_called()
        revalidate.assert_not_called()
        symlink.assert_not_called()
        self.assertEqual(before, snapshot([self.root]))

    def test_protected_entries_skip_all_apply_path_access(self):
        for owner, ident, target in (("user-managed", "user", "tool/user.cfg"),
                                     ("machine-state", "machine", "tool/machine.cfg")):
            current = manifest(owner, ident=ident, target=target)
            before = snapshot([self.root])
            with patch("ktc_manager.executor.canonical_root") as canonical, \
                 patch("ktc_manager.executor.inspect_entry") as inspect, \
                 patch("ktc_manager.executor.revalidate_source") as revalidate, \
                 patch("ktc_manager.executor.os.symlink") as symlink:
                document, code = apply_entry(current, ident, self.repo,
                                             self.klipper, self.config)
            self.assertEqual((document["actions"][0]["code"], document["result"], code),
                             ("PROTECTED_ENTRY", "BLOCKED", 10))
            canonical.assert_not_called()
            inspect.assert_not_called()
            revalidate.assert_not_called()
            symlink.assert_not_called()
            self.assertEqual(before, snapshot([self.root]))

    def test_config_vendor_does_not_resolve_klipper_root(self):
        real_canonical = canonical_root

        def canonical(path):
            if Path(path) == self.klipper:
                raise AssertionError("inactive klipper root resolved")
            return real_canonical(path)

        inspected = {"code": "VENDOR_OK", "target": str(self.config / "tool/target.py"),
                     "source": str(self.repo / "source.txt")}
        with patch("ktc_manager.executor.canonical_root", side_effect=canonical) as resolver, \
             patch("ktc_manager.executor.inspect_entry", return_value=inspected) as inspect, \
             patch("ktc_manager.executor.os.symlink") as symlink:
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("NOOP", 0))
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(Path(resolver.call_args.args[0]), self.config)
        inspect.assert_called_once_with(self.manifest.entries[0], self.repo,
                                        {"config": real_canonical(self.config)})
        symlink.assert_not_called()

    def test_klipper_vendor_does_not_resolve_config_root(self):
        current = manifest(target_root="klipper")
        real_canonical = canonical_root

        def canonical(path):
            if Path(path) == self.config:
                raise AssertionError("inactive config root resolved")
            return real_canonical(path)

        inspected = {"code": "VENDOR_OK", "target": str(self.klipper / "tool/target.py"),
                     "source": str(self.repo / "source.txt")}
        with patch("ktc_manager.executor.canonical_root", side_effect=canonical) as resolver, \
             patch("ktc_manager.executor.inspect_entry", return_value=inspected) as inspect, \
             patch("ktc_manager.executor.os.symlink") as symlink:
            document, code = apply_entry(current, "vendor", self.repo,
                                         self.klipper, self.config)
        self.assertEqual((document["result"], code), ("NOOP", 0))
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(Path(resolver.call_args.args[0]), self.klipper)
        inspect.assert_called_once_with(current.entries[0], self.repo,
                                        {"klipper": real_canonical(self.klipper)})
        symlink.assert_not_called()

    def test_parent_blockers(self):
        missing = manifest(target="missing/target.py")
        document, code = self.blocked_unchanged(missing)
        self.assertEqual((document["actions"][0]["code"], code), ("TARGET_PARENT_MISSING", 10))
        (self.config / "file-parent").write_text("file", encoding="utf-8")
        non_dir = manifest(target="file-parent/target.py")
        document, code = self.blocked_unchanged(non_dir)
        self.assertEqual((document["actions"][0]["code"], code), ("TARGET_PARENT_NOT_DIRECTORY", 10))

    @unittest.skipIf(os.name == "nt", "symlink capability differs on Windows")
    def test_parent_symlink_and_escape(self):
        inside = self.config / "inside"
        inside.mkdir()
        (self.config / "link").symlink_to(inside, target_is_directory=True)
        document, code = self.blocked_unchanged(manifest(target="link/target.py"))
        self.assertEqual((document["actions"][0]["code"], code), ("TARGET_PARENT_SYMLINK", 10))
        outside = self.root / "outside"
        outside.mkdir()
        (self.config / "escape").unlink(missing_ok=True)
        (self.config / "escape").symlink_to(outside, target_is_directory=True)
        document, code = self.blocked_unchanged(manifest(target="escape/target.py"))
        self.assertEqual((document["actions"][0]["code"], code), ("TARGET_ESCAPE", 10))

    def test_source_blockers(self):
        with self.assertRaises(ManifestError):
            manifest(source="../outside.txt")
        for source, expected in (("missing.txt", "SOURCE_MISSING"),):
            document, code = self.blocked_unchanged(manifest(source=source))
            self.assertEqual((document["actions"][0]["code"], code), (expected, 10))
        (self.repo / "source.txt").unlink()
        (self.repo / "source.txt").mkdir()
        document, code = self.blocked_unchanged(self.manifest)
        self.assertEqual((document["actions"][0]["code"], code), ("SOURCE_NOT_FILE", 10))

    @unittest.skipIf(os.name == "nt", "symlink capability differs on Windows")
    def test_source_symlink_is_blocked(self):
        source = self.repo / "source.txt"
        source.unlink()
        try:
            source.symlink_to(self.root / "outside.txt")
        except OSError as exc:
            self.skipTest("symlink unavailable: %s" % exc)
        document, code = self.blocked_unchanged(self.manifest)
        self.assertEqual((document["actions"][0]["code"], code), ("SOURCE_NOT_FILE", 10))

    @unittest.skipIf(os.name == "nt", "permission mode semantics differ on Windows")
    def test_unwritable_parent(self):
        if os.geteuid() == 0:
            self.skipTest("effective root bypasses POSIX permissions")
        self.config.joinpath("tool").chmod(0o500)
        try:
            before = snapshot([self.root])
            document, code = self.apply()
            self.assertEqual((document["actions"][0]["code"], code), ("PERMISSION_DENIED", 10))
            self.assertEqual(before, snapshot([self.root]))
        finally:
            self.config.joinpath("tool").chmod(0o700)

    def test_mocked_syscall_errors_are_safe(self):
        target = self.config / "tool/target.py"
        before = snapshot([self.root])
        with patch("ktc_manager.executor.os.symlink", side_effect=PermissionError(errno.EACCES, "denied")):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("BLOCKED", 10))
        self.assertEqual(before, snapshot([self.root]))
        sentinel = target
        raced_snapshot = {}
        def race(*args, **kwargs):
            nonlocal raced_snapshot
            Path(sentinel).write_bytes(b"racer sentinel")
            raced_snapshot = snapshot([self.root])
            raise FileExistsError(errno.EEXIST, "race")
        with patch("ktc_manager.executor.os.symlink", side_effect=race):
            document, code = self.apply()
        self.assertEqual((document["actions"][0]["code"], code), ("TARGET_EXISTS_RACE", 10))
        self.assertEqual(raced_snapshot, snapshot([self.root]))
        self.assertEqual(target.read_bytes(), b"racer sentinel")
        self.assertFalse(target.is_symlink())
        target.unlink()
        win_error = OSError("privilege")
        win_error.winerror = 1314
        before = snapshot([self.root])
        with patch("ktc_manager.executor.os.symlink", side_effect=win_error):
            document, code = self.apply()
        self.assertEqual((document["actions"][0]["code"], code), ("PERMISSION_DENIED", 10))
        self.assertEqual(before, snapshot([self.root]))

    def test_apply_root_unavailable_is_safe(self):
        missing_root = self.root / "missing-config"
        before = snapshot([self.root])
        with patch("ktc_manager.executor.os.symlink") as symlink:
            document, code = apply_entry(self.manifest, "vendor", self.repo,
                                         self.klipper, missing_root)
        self.assertEqual((document["actions"][0]["code"], code),
                         ("TARGET_ROOT_UNAVAILABLE", 10))
        symlink.assert_not_called()
        self.assertEqual(before, snapshot([self.root]))

    def test_source_unreadable_is_safe(self):
        source = self.repo / "source.txt"
        def access(path, mode):
            return False if same_existing_path(path, source) else True
        before = snapshot([self.root])
        with patch("ktc_manager.inspector.os.access", side_effect=access), \
             patch("ktc_manager.executor.os.symlink") as symlink:
            document, code = self.apply()
        self.assertEqual((document["actions"][0]["code"], code),
                         ("SOURCE_UNREADABLE", 10))
        symlink.assert_not_called()
        self.assertEqual(before, snapshot([self.root]))

    def test_source_revalidation_blocks_without_syscall(self):
        before = snapshot([self.root])
        with patch("ktc_manager.executor.revalidate_source",
                   return_value=("SOURCE_ESCAPE", self.repo / "source.txt")), \
             patch("ktc_manager.executor.os.symlink") as symlink:
            document, code = self.apply()
        self.assertEqual((document["actions"][0]["code"], code), ("SOURCE_ESCAPE", 10))
        symlink.assert_not_called()
        self.assertEqual(before, snapshot([self.root]))

    def test_post_inspect_errors_are_indeterminate(self):
        missing = {"code": "VENDOR_MISSING", "target": str(self.config / "tool/target.py"),
                   "source": str(self.repo / "source.txt")}
        with patch("ktc_manager.executor.inspect_entry", side_effect=[missing, missing, RuntimeError("post")]), \
             patch("ktc_manager.executor.revalidate_source", return_value=(None, self.repo / "source.txt")), \
             patch("ktc_manager.executor.os.symlink"):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("INDETERMINATE", 20))

        with patch("ktc_manager.executor.inspect_entry", side_effect=[missing, missing, OSError(errno.EIO, "post")]), \
             patch("ktc_manager.executor.revalidate_source", return_value=(None, self.repo / "source.txt")), \
             patch("ktc_manager.executor.os.symlink", side_effect=OSError(errno.EIO, "create")):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("INDETERMINATE", 20))

    def test_source_lstat_reparse_is_blocked_initial_and_final(self):
        source = self.repo / "source.txt"
        real_lstat = os.lstat
        reparse = type("Stat", (), {"st_mode": stat.S_IFREG, "st_file_attributes": 0x400})()
        with patch("ktc_manager.inspector.os.lstat", side_effect=lambda path: reparse if same_existing_path(path, source) else real_lstat(path)):
            self.assertEqual(_source_state(self.manifest.entries[0], self.repo)[0], "SOURCE_NOT_FILE")
            with patch("ktc_manager.executor.os.symlink") as symlink:
                document, code = self.apply()
            self.assertEqual((document["actions"][0]["code"], code), ("SOURCE_NOT_FILE", 10))
            symlink.assert_not_called()
        regular = type("Stat", (), {"st_mode": stat.S_IFREG, "st_file_attributes": 0})()
        calls = []
        def changing_lstat(path):
            if same_existing_path(path, source):
                calls.append(1)
                return regular if len(calls) == 1 else reparse
            return real_lstat(path)
        with patch("ktc_manager.inspector.canonical_root", return_value=self.repo), \
             patch.object(Path, "resolve", return_value=source), \
             patch("ktc_manager.inspector.os.lstat", side_effect=changing_lstat):
            self.assertEqual(revalidate_source(self.manifest.entries[0], self.repo)[0], "SOURCE_CHANGED")

    def test_parent_lstat_errors_are_stable_blockers(self):
        root = canonical_root(self.config)
        target_parent = root / "tool"
        real_lstat = os.lstat
        before = snapshot([self.root])
        target = target_parent / "target.py"
        for error, expected in ((PermissionError("denied"), "PERMISSION_DENIED"),
                                (OSError(errno.EIO, "changed"), "TARGET_PARENT_CHANGED"),
                                (FileNotFoundError("gone"), "TARGET_PARENT_MISSING")):
            def failing_lstat(path, error=error):
                if same_existing_path(path, target_parent):
                    raise error
                return real_lstat(path)
            with patch("ktc_manager.inspector.os.lstat", side_effect=failing_lstat):
                self.assertEqual(_parent_structure(target, root), expected)
        self.assertEqual(before, snapshot([self.root]))

        reparse_dir = type("Stat", (), {"st_mode": stat.S_IFDIR, "st_file_attributes": 0x400})()
        def reparse_parent(path):
            if same_existing_path(path, target_parent):
                return reparse_dir
            return real_lstat(path)
        with patch("ktc_manager.inspector.os.lstat", side_effect=reparse_parent):
            self.assertEqual(_parent_structure(target, root), "TARGET_PARENT_SYMLINK")

    def test_apply_id_cardinality_errors_are_deterministic(self):
        cases = (["apply"], ["apply", "--id", "vendor", "--id", "vendor"])
        for output_format in ("text", "json"):
            for args in cases:
                stream = io.StringIO()
                error = io.StringIO()
                with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(error):
                    self.assertEqual(main(args + ["--format", output_format]), 64)
                self.assertNotIn("usage:", stream.getvalue().lower() + error.getvalue().lower())
                self.assertNotIn("\x1b[", stream.getvalue() + error.getvalue())
                if output_format == "text":
                    self.assertEqual(stream.getvalue(), "")
                    self.assertEqual(error.getvalue().count("\n"), 1)
                    self.assertTrue(error.getvalue().startswith("KTCM1 error "))
                else:
                    self.assertEqual(error.getvalue(), "")
                    document = json.loads(stream.getvalue())
                    self.assertEqual(document["schema_version"], 1)
                    self.assertIn("exactly one --id", document["error"])

    def test_applied_and_noop_result_shapes_are_portable(self):
        missing = {"code": "VENDOR_MISSING", "target": str(self.config / "tool/target.py"),
                   "source": str(self.repo / "source.txt")}
        ok = dict(missing, code="VENDOR_OK")
        with patch("ktc_manager.executor.inspect_entry", side_effect=[missing, missing, ok]), \
             patch("ktc_manager.executor.revalidate_source",
                   return_value=(None, self.repo / "source.txt")), \
             patch("ktc_manager.executor.os.symlink"):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("APPLIED", 0))
        self.assertEqual(document["summary"], {"total": 1, "blockers": 0, "created": 1, "noop": 0})
        with patch("ktc_manager.executor.inspect_entry", return_value=ok):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("NOOP", 0))

    def test_generic_failure_and_indeterminate(self):
        before = snapshot([self.root])
        with patch("ktc_manager.executor.os.symlink", side_effect=OSError(errno.EIO, "io")):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("FAILED", 20))
        self.assertEqual(before, snapshot([self.root]))

        self.require_symlink()
        real_symlink = os.symlink

        def create_then_fail(source, target, target_is_directory=False):
            real_symlink(source, target, target_is_directory=target_is_directory)
            raise OSError(errno.EIO, "after create")

        with patch("ktc_manager.executor.os.symlink", side_effect=create_then_fail):
            document, code = self.apply()
        self.assertEqual((document["result"], code), ("INDETERMINATE", 20))

    def test_json_and_text_apply_are_deterministic(self):
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps({
            "schema_version": 1, "profile": "apply-test", "entries": [
                {"id": "vendor", "owner": "vendor-managed", "source": "source.txt",
                 "target_root": "config", "target": "tool/target.py", "delivery": "symlink"}
            ]
        }), encoding="utf-8")
        for output_format in ("json", "text"):
            args = ["apply", "--id", "unknown", "--manifest", str(manifest_path),
                    "--repo-root", str(self.repo), "--config-root", str(self.config),
                    "--klipper-root", str(self.klipper), "--format", output_format]
            outputs = []
            for _ in range(2):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    self.assertEqual(main(args), 10)
                outputs.append(stream.getvalue())
            self.assertEqual(outputs[0], outputs[1])
            self.assertNotIn("\x1b[", outputs[0])
            if output_format == "json":
                self.assertEqual(json.loads(outputs[0])["result"], "BLOCKED")

    def test_cli_apply_error_exit_boundaries(self):
        self.assertEqual(main(["apply", "--id", "vendor", "--manifest", str(self.root / "missing.json"),
                               "--format", "json"]), 65)
        manifest_path = self.root / "valid.json"
        manifest_path.write_text(json.dumps({
            "schema_version": 1, "profile": "apply-test", "entries": [
                {"id": "vendor", "owner": "vendor-managed", "source": "source.txt",
                 "target_root": "config", "target": "tool/target.py", "delivery": "symlink"}
            ]
        }), encoding="utf-8")
        with patch("ktc_manager.cli.apply_entry", side_effect=RuntimeError("internal")):
            self.assertEqual(main(["apply", "--id", "vendor", "--manifest", str(manifest_path),
                                   "--repo-root", str(self.repo), "--config-root", str(self.config),
                                   "--klipper-root", str(self.klipper), "--format", "json"]), 70)
