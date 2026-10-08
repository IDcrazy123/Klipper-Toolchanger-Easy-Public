import glob
import json
import os
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ("ownership-v1.json", "ownership-v1-tap-per-tool.json")
INCLUDE_ID = "vendor-toolchanger-include"
COMMON_VENDOR_INCLUDES = {
    "homing.cfg": "toolchanger/readonly-configs/homing.cfg",
    "toolchanger.cfg": "toolchanger/readonly-configs/toolchanger.cfg",
    "toolchanger-macros.cfg": "toolchanger/readonly-configs/toolchanger-macros.cfg",
    "calibrate-offsets.cfg": "toolchanger/readonly-configs/calibrate-offsets.cfg",
    "crash-detection.cfg": "toolchanger/readonly-configs/crash-detection.cfg",
}


class IncludeGraphError(Exception):
    pass


class MissingInclude(IncludeGraphError):
    pass


class IncludeEscapesConfig(IncludeGraphError):
    pass


class IncludeOwnershipMismatch(IncludeGraphError):
    pass


class RecursiveInclude(IncludeGraphError):
    pass


def walk_includes(config_root, entry_target, source_text, ownership, required_owners):
    """Model Klipper include resolution without importing or running Klipper."""
    root = Path(os.path.abspath(config_root))
    root_file = root.joinpath(*entry_target.split("/"))
    graph = []
    recursion_stack = set()

    def visit(filename, text):
        key = os.path.normcase(os.path.abspath(filename))
        if key in recursion_stack:
            raise RecursiveInclude(str(filename))
        recursion_stack.add(key)
        try:
            for raw_line in text.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not (line.startswith("[include ") and line.endswith("]")):
                    continue
                spec = line[len("[include "):-1].strip()
                pattern = os.path.join(str(filename.parent), spec)
                normalized_pattern = Path(os.path.abspath(pattern))
                try:
                    normalized_pattern.relative_to(root)
                except ValueError as exc:
                    raise IncludeEscapesConfig(str(normalized_pattern)) from exc
                pattern = str(normalized_pattern)
                matches = sorted(glob.glob(pattern))
                if not matches and not glob.has_magic(pattern):
                    raise MissingInclude(pattern)
                if not matches:
                    graph.append((filename, spec, None, None))
                    continue
                for match in matches:
                    child = Path(os.path.abspath(match))
                    try:
                        relative = child.relative_to(root).as_posix()
                    except ValueError as exc:
                        raise IncludeEscapesConfig(str(child)) from exc
                    owner = ownership.get(relative)
                    expected = required_owners.get(relative)
                    if owner is None or (expected is not None and owner != expected):
                        raise IncludeOwnershipMismatch(
                            "%s: owner=%r expected=%r" % (relative, owner, expected))
                    graph.append((filename, spec, relative, owner))
                    visit(child, child.read_text(encoding="utf-8"))
        finally:
            recursion_stack.remove(key)

    visit(root_file, source_text)
    return graph


def write_config_file(root, relative, contents=""):
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


class IncludeGraphTests(unittest.TestCase):
    def test_both_profiles_resolve_include_source_from_manifest_target(self):
        for manifest_name in MANIFESTS:
            with self.subTest(manifest=manifest_name), tempfile.TemporaryDirectory() as directory:
                manifest = json.loads((ROOT / "manifests" / manifest_name).read_text(encoding="utf-8"))
                entries = manifest["entries"]
                include_entry = next(entry for entry in entries if entry["id"] == INCLUDE_ID)
                self.assertEqual(include_entry["owner"], "vendor-managed")
                source_path = ROOT / include_entry["source"]
                source_text = source_path.read_text(encoding="utf-8")
                config_root = Path(directory) / "config"
                target_path = config_root.joinpath(*include_entry["target"].split("/"))
                self.assertNotEqual(source_path.parent, target_path.parent)

                owner_by_target = {
                    entry["target"]: entry["owner"] for entry in entries
                    if entry["target_root"] == "config"
                }
                expected_vendor = list(COMMON_VENDOR_INCLUDES.items())
                if manifest_name == "ownership-v1-tap-per-tool.json":
                    expected_vendor.insert(1, (
                        "tool_detection.cfg", "toolchanger/readonly-configs/tool_detection.cfg"))
                user_config = "toolchanger/toolchanger-config.cfg"
                vendor_config_sources = {
                    entry["target"]: entry["source"] for entry in entries
                    if entry["target_root"] == "config"
                    and entry["owner"] == "vendor-managed"
                    and entry["target"].endswith(".cfg")
                }
                self.assertTrue(set(target for _, target in expected_vendor)
                                <= set(vendor_config_sources))
                # Materialize source contents at simulated targets; no symlinks are created.
                for target, source in vendor_config_sources.items():
                    contents = (ROOT / source).read_text(encoding="utf-8")
                    write_config_file(config_root, target, contents)
                write_config_file(config_root, user_config)

                graph = walk_includes(config_root, include_entry["target"], source_text,
                                      owner_by_target, owner_by_target)
                expected_edges = [(spec, target, "vendor-managed")
                                  for spec, target in expected_vendor]
                expected_edges.extend((
                    ("../tools/T*.cfg", None, None),
                    ("../toolchanger-config.cfg", user_config, "user-managed"),
                ))
                self.assertEqual([(spec, target, owner)
                                  for _, spec, target, owner in graph], expected_edges)

                tool_include = next(spec for _, spec, target, _ in graph
                                    if spec == "../tools/T*.cfg" and target is None)
                self.assertEqual(tool_include, "../tools/T*.cfg")
                tool_area = target_path.parent / "../tools"
                self.assertEqual(Path(os.path.abspath(tool_area)),
                                 config_root / "toolchanger" / "tools")
                tool_entries = [entry for entry in entries
                                if entry["target"].startswith("toolchanger/tools/")]
                self.assertTrue(tool_entries)
                self.assertTrue(all(entry["owner"] == "user-managed" for entry in tool_entries))
                self.assertFalse(any((config_root / entry["target"]).exists()
                                     for entry in tool_entries))

    def test_direct_missing_include_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "config"
            target = "toolchanger/readonly-configs/main.cfg"
            write_config_file(root, target, "[include absent.cfg]\n")
            with self.assertRaises(MissingInclude):
                walk_includes(root, target, "[include absent.cfg]\n",
                              {target: "vendor-managed"}, {})

    def test_include_with_wrong_owner_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "config"
            main = "toolchanger/readonly-configs/main.cfg"
            leaf = "toolchanger/readonly-configs/leaf.cfg"
            write_config_file(root, main, "[include leaf.cfg]\n")
            write_config_file(root, leaf)
            with self.assertRaises(IncludeOwnershipMismatch):
                walk_includes(root, main, "[include leaf.cfg]\n",
                              {main: "vendor-managed", leaf: "machine-state"},
                              {leaf: "vendor-managed"})

    def test_include_escape_outside_config_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "config"
            main = "toolchanger/readonly-configs/main.cfg"
            write_config_file(root, main, "[include ../../../outside.cfg]\n")
            (base / "outside.cfg").write_text("", encoding="utf-8")
            with self.assertRaises(IncludeEscapesConfig):
                walk_includes(root, main, "[include ../../../outside.cfg]\n",
                              {main: "vendor-managed"}, {})

            wildcard = "[include ../../../missing/*.cfg]\n"
            write_config_file(root, main, wildcard)
            with self.assertRaises(IncludeEscapesConfig):
                walk_includes(root, main, wildcard, {main: "vendor-managed"}, {})

    def test_nested_valid_includes_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "config"
            main = "toolchanger/readonly-configs/main.cfg"
            nested = "toolchanger/readonly-configs/nested/child.cfg"
            leaf = "toolchanger/readonly-configs/nested/deep/leaf.cfg"
            write_config_file(root, main, "[include nested/child.cfg]\n")
            write_config_file(root, nested, "[include deep/leaf.cfg]\n")
            write_config_file(root, leaf)
            owners = {main: "vendor-managed", nested: "vendor-managed",
                      leaf: "vendor-managed"}
            graph = walk_includes(root, main, "[include nested/child.cfg]\n", owners,
                                  owners)
            self.assertEqual({target for _, _, target, _ in graph}, {nested, leaf})

    def test_repeated_dag_includes_are_allowed_after_stack_unwinds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "config"
            main = "toolchanger/readonly-configs/main.cfg"
            child = "toolchanger/readonly-configs/child.cfg"
            leaf = "toolchanger/readonly-configs/leaf.cfg"
            main_text = "[include child.cfg]\n[include child.cfg]\n"
            write_config_file(root, main, main_text)
            write_config_file(root, child, "[include leaf.cfg]\n")
            write_config_file(root, leaf)
            owners = {main: "vendor-managed", child: "vendor-managed",
                      leaf: "vendor-managed"}
            graph = walk_includes(root, main, main_text, owners, owners)
            self.assertEqual(Counter(target for _, _, target, _ in graph),
                             Counter({child: 2, leaf: 2}))

    def test_recursion_is_rejected_only_while_file_is_on_stack(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "config"
            main = "toolchanger/readonly-configs/main.cfg"
            child = "toolchanger/readonly-configs/child.cfg"
            main_text = "[include child.cfg]\n"
            write_config_file(root, main, main_text)
            write_config_file(root, child, "[include main.cfg]\n")
            owners = {main: "vendor-managed", child: "vendor-managed"}
            with self.assertRaises(RecursiveInclude):
                walk_includes(root, main, main_text, owners, owners)
