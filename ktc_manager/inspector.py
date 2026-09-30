import hashlib
import json
import os
from pathlib import Path

from .model import Entry, Manifest


BLOCKER_CODES = {
    "VENDOR_MISSING": False,
    "VENDOR_OK": False,
    "PROTECTED_PRESENT": False,
    "PROTECTED_MISSING": False,
}


def _lexists(path):
    return path.exists() or path.is_symlink()


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


def _target_permission(target):
    current = target.parent
    while not _lexists(current) and current != current.parent:
        current = current.parent
    return os.access(str(current), os.W_OK | os.X_OK)


def _source_state(entry, repo_root):
    source = _source_path(entry, repo_root)
    if not source.exists() and not source.is_symlink():
        return "SOURCE_MISSING", source
    if source.is_symlink() or not source.is_file():
        return "SOURCE_NOT_FILE", source
    if not os.access(str(source), os.R_OK):
        return "SOURCE_UNREADABLE", source
    try:
        source.resolve(strict=True).relative_to(repo_root)
    except (OSError, RuntimeError, ValueError):
        return "SOURCE_NOT_FILE", source
    return None, source


def inspect(manifest: Manifest, repo_root, klipper_root, config_root):
    repo = canonical_root(repo_root)
    roots = {"klipper": canonical_root(klipper_root), "config": canonical_root(config_root)}
    results = []
    for entry in manifest.entries:
        target = _target_path(entry, roots)
        root = roots[entry.target_root]
        source_hint = _source_path(entry, repo) if entry.owner == "vendor-managed" else None
        if not root.exists() or not root.is_dir():
            results.append(_result(entry, "TARGET_ROOT_UNAVAILABLE", target, source_hint))
            continue
        if _target_escape(target, root):
            results.append(_result(entry, "TARGET_ESCAPE", target, source_hint))
            continue
        if not _target_permission(target):
            results.append(_result(entry, "PERMISSION_DENIED", target, source_hint))
            continue
        if entry.owner == "vendor-managed":
            source_code, source = _source_state(entry, repo)
            if source_code:
                results.append(_result(entry, source_code, target))
                continue
            if not target.exists() and not target.is_symlink():
                results.append(_result(entry, "VENDOR_MISSING", target, source))
            elif target.is_dir() and not target.is_symlink():
                results.append(_result(entry, "VENDOR_COLLISION_DIRECTORY", target, source))
            elif target.is_symlink():
                try:
                    same = target.resolve(strict=True) == source.resolve(strict=True)
                except (OSError, RuntimeError):
                    results.append(_result(entry, "VENDOR_BROKEN_LINK", target, source))
                    continue
                results.append(_result(entry, "VENDOR_OK" if same else "VENDOR_WRONG_LINK", target, source))
            elif target.is_file():
                results.append(_result(entry, "VENDOR_COLLISION_FILE", target, source))
            else:
                results.append(_result(entry, "VENDOR_COLLISION_OTHER", target, source))
        else:
            code = "PROTECTED_PRESENT" if target.exists() or target.is_symlink() else "PROTECTED_MISSING"
            results.append(_result(entry, code, target))
    return results


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
