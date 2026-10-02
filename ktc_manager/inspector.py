import hashlib
import json
import os
import stat
from pathlib import Path

from .model import Entry, Manifest


BLOCKER_CODES = {
    "VENDOR_MISSING": False,
    "VENDOR_OK": False,
    "PROTECTED_PRESENT": False,
    "PROTECTED_MISSING": False,
}


def _lexists(path):
    try:
        return path.exists() or _is_link_or_reparse(path)
    except OSError:
        return False


def _is_link_or_reparse(path):
    info = os.lstat(str(path))
    return _stat_is_link_or_reparse(info)


def _stat_is_link_or_reparse(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def canonical_root(path):
    value = Path(path).expanduser()
    try:
        return value.resolve(strict=False)
    except (OSError, RuntimeError):
        return value.absolute()


def _inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _target_path(entry, roots):
    root = roots[entry.target_root]
    return root.joinpath(*entry.target.split("/"))


def _source_path(entry, repo_root):
    return repo_root.joinpath(*entry.source.split("/"))


def _target_escape(target, root):
    if not root.exists() or not root.is_dir():
        return False
    current = target.parent
    while not _lexists(current) and current != current.parent:
        current = current.parent
    try:
        existing_parent = current.resolve(strict=True)
    except (OSError, RuntimeError):
        return True
    if not _inside(existing_parent, root):
        return True
    return False


def _source_state(entry, repo_root):
    source = _source_path(entry, repo_root)
    try:
        info = os.lstat(str(source))
    except FileNotFoundError:
        return "SOURCE_MISSING", source
    except (OSError, RuntimeError):
        return "SOURCE_NOT_FILE", source
    if _stat_is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        return "SOURCE_NOT_FILE", source
    if not os.access(str(source), os.R_OK):
        return "SOURCE_UNREADABLE", source
    try:
        source.resolve(strict=True).relative_to(repo_root)
    except (OSError, RuntimeError, ValueError):
        return "SOURCE_NOT_FILE", source
    return None, source


def revalidate_source(entry, repo_root):
    """Recheck the trusted source immediately before the apply syscall."""
    repo = canonical_root(repo_root)
    source = _source_path(entry, repo)
    try:
        info = os.lstat(str(source))
    except (OSError, RuntimeError):
        return "SOURCE_CHANGED", source
    if _stat_is_link_or_reparse(info):
        try:
            resolved = source.resolve(strict=False)
        except (OSError, RuntimeError):
            return "SOURCE_CHANGED", source
        return ("SOURCE_ESCAPE" if not _inside(resolved, repo) else "SOURCE_CHANGED"), source
    if not stat.S_ISREG(info.st_mode) or not os.access(str(source), os.R_OK):
        return "SOURCE_CHANGED", source
    try:
        resolved = source.resolve(strict=True)
    except (OSError, RuntimeError):
        return "SOURCE_CHANGED", source
    if not _inside(resolved, repo):
        return "SOURCE_ESCAPE", source
    try:
        final_info = os.lstat(str(source))
    except OSError:
        return "SOURCE_CHANGED", source
    if _stat_is_link_or_reparse(final_info) or not stat.S_ISREG(final_info.st_mode):
        return "SOURCE_CHANGED", source
    return None, resolved


def _parent_structure(target, root):
    parent = target.parent
    try:
        parent_info = os.lstat(str(parent))
    except FileNotFoundError:
        return "TARGET_PARENT_MISSING"
    except PermissionError:
        return "PERMISSION_DENIED"
    except OSError:
        return "TARGET_PARENT_CHANGED"
    if not _inside(parent, root):
        return "TARGET_ESCAPE"
    current = parent
    while True:
        try:
            current_info = os.lstat(str(current))
        except FileNotFoundError:
            return "TARGET_PARENT_MISSING"
        except PermissionError:
            return "PERMISSION_DENIED"
        except OSError:
            return "TARGET_PARENT_CHANGED"
        if _stat_is_link_or_reparse(current_info):
            try:
                resolved = current.resolve(strict=True)
            except FileNotFoundError:
                return "TARGET_ESCAPE"
            except PermissionError:
                return "PERMISSION_DENIED"
            except (OSError, RuntimeError):
                return "TARGET_PARENT_CHANGED"
            return "TARGET_ESCAPE" if not _inside(resolved, root) else "TARGET_PARENT_SYMLINK"
        if current == root:
            break
        current = current.parent
        if not _inside(current, root):
            return "TARGET_ESCAPE"
    if not stat.S_ISDIR(parent_info.st_mode):
        return "TARGET_PARENT_NOT_DIRECTORY"
    return None


def _parent_permission(target):
    return os.access(str(target.parent), os.W_OK | os.X_OK)


def inspect_entry(entry: Entry, repo_root, roots):
    repo = canonical_root(repo_root)
    root = roots[entry.target_root]
    target = _target_path(entry, roots)
    source_hint = _source_path(entry, repo) if entry.owner == "vendor-managed" else None
    if not root.exists() or not root.is_dir():
        return _result(entry, "TARGET_ROOT_UNAVAILABLE", target, source_hint)
    if _target_escape(target, root):
        return _result(entry, "TARGET_ESCAPE", target, source_hint)
    if entry.owner != "vendor-managed":
        code = "PROTECTED_PRESENT" if _lexists(target) else "PROTECTED_MISSING"
        return _result(entry, code, target)

    source_code, source = _source_state(entry, repo)
    source_hint = source
    if source_code:
        return _result(entry, source_code, target)
    structure_code = _parent_structure(target, root)
    if structure_code:
        return _result(entry, structure_code, target, source_hint)
    if _lexists(target):
        if target.is_dir() and not target.is_symlink():
            return _result(entry, "VENDOR_COLLISION_DIRECTORY", target, source)
        if target.is_symlink():
            try:
                same = target.resolve(strict=True) == source.resolve(strict=True)
            except (OSError, RuntimeError):
                return _result(entry, "VENDOR_BROKEN_LINK", target, source)
            return _result(entry, "VENDOR_OK" if same else "VENDOR_WRONG_LINK", target, source)
        if target.is_file():
            return _result(entry, "VENDOR_COLLISION_FILE", target, source)
        return _result(entry, "VENDOR_COLLISION_OTHER", target, source)
    if not _parent_permission(target):
        return _result(entry, "PERMISSION_DENIED", target, source_hint)
    return _result(entry, "VENDOR_MISSING", target, source_hint)


def inspect(manifest: Manifest, repo_root, klipper_root, config_root):
    roots = {"klipper": canonical_root(klipper_root), "config": canonical_root(config_root)}
    return [inspect_entry(entry, repo_root, roots) for entry in manifest.entries]


def _result(entry, code, target, source=None):
    result = {"id": entry.id, "owner": entry.owner, "code": code, "target": target.as_posix()}
    if source is not None:
        result["source"] = source.as_posix()
    return result


def plan_actions(results):
    mapping = {
        "VENDOR_OK": "NOOP",
        "VENDOR_MISSING": "WOULD_LINK",
        "PROTECTED_PRESENT": "PRESERVE",
        "PROTECTED_MISSING": "PRESERVE_MISSING",
    }
    actions = []
    for result in results:
        action = mapping.get(result["code"], "BLOCKED")
        item = dict(result)
        item["action"] = action
        actions.append(item)
    return actions


def summary(results, key="code"):
    counts = {}
    for result in results:
        value = result[key]
        counts[value] = counts.get(value, 0) + 1
    if key == "action":
        blockers = sum(1 for result in results if result[key] == "BLOCKED")
    else:
        blockers = sum(1 for result in results if result[key] not in BLOCKER_CODES)
    return {"total": len(results), "blockers": blockers, "by_code": counts}


def snapshot(paths):
    """Test helper: read-only snapshot of path metadata and content identity."""
    output = {}
    pending = [Path(raw) for raw in paths]
    seen = set()
    while pending:
        path = pending.pop(0)
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        item = {"exists": path.exists() or path.is_symlink(), "type": "missing"}
        if path.is_symlink():
            item["type"] = "symlink"
            item["link"] = os.readlink(str(path))
            item["mode"] = os.lstat(str(path)).st_mode
        elif path.is_file():
            item["type"] = "file"
            stat = path.stat()
            item["mode"] = stat.st_mode
            item["hash"] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            item["type"] = "directory"
            item["mode"] = path.stat().st_mode
            try:
                pending[0:0] = sorted(path.iterdir(), key=lambda child: child.as_posix())
            except OSError:
                item["error"] = "unreadable"
        output[key] = item
    return output


def output_document(command, manifest, results, dry_run=False):
    key = "actions" if command == "plan" else "results"
    values = plan_actions(results) if command == "plan" else results
    return {
        "schema_version": 1,
        "command": command,
        "profile": manifest.profile,
        "dry_run": dry_run,
        "summary": summary(values, "action" if command == "plan" else "code"),
        key: values,
    }
