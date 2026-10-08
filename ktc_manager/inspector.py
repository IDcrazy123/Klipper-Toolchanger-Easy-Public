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
    return stat.S_ISLNK(info.st_mode) or bool((getattr(info, "st_file_attributes", 0) or 0) & 0x400)


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
    except PermissionError:
        return "SOURCE_UNREADABLE", source
    except (OSError, RuntimeError):
        return "SOURCE_NOT_FILE", source
    if _stat_is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        return "SOURCE_NOT_FILE", source
    if not os.access(str(source), os.R_OK):
        return "SOURCE_UNREADABLE", source
    try:
        source.resolve(strict=True).relative_to(repo_root)
    except PermissionError:
        return "SOURCE_UNREADABLE", source
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


def _file_state(info):
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        bool((getattr(info, "st_file_attributes", 0) or 0) & 0x400),
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1000000000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1000000000)),
    )


def _ordinary_regular(info):
    return stat.S_ISREG(info.st_mode) and not _stat_is_link_or_reparse(info)


def _cross_handle_state(info):
    return _file_state(info)[:-1]


def _stream_file(path, role):
    changed = "SOURCE_CHANGED" if role == "source" else "TARGET_CHANGED"
    unreadable = "SOURCE_UNREADABLE" if role == "source" else "TARGET_UNREADABLE"
    try:
        initial_info = os.lstat(str(path))
    except PermissionError:
        return unreadable, None
    except OSError:
        return changed, None
    if not _ordinary_regular(initial_info):
        return changed, None
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return changed, None
    except OSError:
        return unreadable, None
    raw = hashlib.sha256()
    normalized = hashlib.sha256()
    raw_size = 0
    normalized_size = 0
    pending_cr = False
    try:
        try:
            opened_info = os.fstat(fd)
        except OSError:
            return unreadable, None
        if (_cross_handle_state(opened_info) != _cross_handle_state(initial_info) or
                not _ordinary_regular(opened_info)):
            return changed, None
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except OSError:
                return unreadable, None
            if not chunk:
                break
            raw.update(chunk)
            raw_size += len(chunk)
            normalized_chunk = bytearray()
            for byte in chunk:
                if pending_cr:
                    if byte == 10:
                        normalized_chunk.append(10)
                        pending_cr = False
                        continue
                    normalized_chunk.append(13)
                    pending_cr = False
                if byte == 13:
                    pending_cr = True
                else:
                    normalized_chunk.append(byte)
            normalized.update(normalized_chunk)
            normalized_size += len(normalized_chunk)
        if pending_cr:
            normalized.update(b"\r")
            normalized_size += 1
        try:
            final_info = os.fstat(fd)
        except OSError:
            return unreadable, None
        if (_file_state(final_info) != _file_state(opened_info) or
                not _ordinary_regular(final_info)):
            return changed, None
    finally:
        os.close(fd)
    return None, {
        "raw_sha256": raw.hexdigest(),
        "raw_size": raw_size,
        "normalized_sha256": normalized.hexdigest(),
        "normalized_size": normalized_size,
        "state": _file_state(initial_info),
    }


def _collision_fingerprints(entry, repo, root, source, target):
    """Read-only fingerprints trust user-owned repo/source and target roots/parents.

    This assumes no concurrent path updater while the checks and reads run; it does
    not claim to eliminate TOCTOU risk against an actor mutating those trusted paths.
    """
    source_code, source_check = _source_state(entry, repo)
    if source_code:
        return source_code, None
    source = source_check
    structure_code = _parent_structure(target, root)
    if structure_code:
        return structure_code, None
    source_code, source_fingerprint = _stream_file(source, "source")
    if source_code:
        return source_code, None
    target_code, target_fingerprint = _stream_file(target, "target")
    if target_code:
        return target_code, None
    try:
        source_final = os.lstat(str(source))
    except PermissionError:
        return "SOURCE_UNREADABLE", None
    except OSError:
        return "SOURCE_CHANGED", None
    if not _ordinary_regular(source_final):
        return "SOURCE_CHANGED", None
    try:
        target_final = os.lstat(str(target))
    except PermissionError:
        return "TARGET_UNREADABLE", None
    except OSError:
        return "TARGET_CHANGED", None
    if not _ordinary_regular(target_final):
        return "TARGET_CHANGED", None
    if _file_state(source_final) != source_fingerprint["state"]:
        return "SOURCE_CHANGED", None
    if _file_state(target_final) != target_fingerprint["state"]:
        return "TARGET_CHANGED", None
    source_code, source_check = _source_state(entry, repo)
    if source_code:
        return source_code, None
    source = source_check
    structure_code = _parent_structure(target, root)
    if structure_code:
        return structure_code, None
    if (source_fingerprint["raw_size"] == target_fingerprint["raw_size"] and
            source_fingerprint["raw_sha256"] == target_fingerprint["raw_sha256"]):
        relation = "IDENTICAL_BYTES"
    elif (source_fingerprint["normalized_size"] == target_fingerprint["normalized_size"] and
          source_fingerprint["normalized_sha256"] == target_fingerprint["normalized_sha256"]):
        relation = "EQUAL_AFTER_CRLF_NORMALIZATION"
    else:
        relation = "DIFFERENT"
    return None, {
        "source_sha256": source_fingerprint["raw_sha256"],
        "target_sha256": target_fingerprint["raw_sha256"],
        "content_relation": relation,
    }


def _selected_missing_source_digest(entry, repo, roots, result):
    source_code, source = _source_state(entry, repo)
    if source_code:
        result["code"] = source_code
        return result
    source_code, fingerprint = _stream_file(source, "source")
    if source_code:
        result["code"] = source_code
        return result

    post = inspect_entry(entry, repo, roots)
    if post["code"] != "VENDOR_MISSING":
        if post["code"].startswith("VENDOR_"):
            post["code"] = "TARGET_CHANGED"
        return post
    try:
        final_info = os.lstat(post["source"])
    except PermissionError:
        post["code"] = "SOURCE_UNREADABLE"
        return post
    except OSError:
        post["code"] = "SOURCE_CHANGED"
        return post
    if (not _ordinary_regular(final_info) or
            _file_state(final_info) != fingerprint["state"]):
        post["code"] = "SOURCE_CHANGED"
        return post

    post["source_sha256"] = fingerprint["raw_sha256"]
    return post


def inspect_entry(entry: Entry, repo_root, roots):
    repo = canonical_root(repo_root) if entry.owner == "vendor-managed" else None
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


def inspect(manifest: Manifest, repo_root, klipper_root, config_root, entry_id=None):
    if entry_id is not None:
        selected = [entry for entry in manifest.entries if entry.id == entry_id]
        if not selected:
            return [{"id": entry_id, "owner": "", "code": "UNKNOWN_ID", "target": ""}]
    else:
        selected = list(manifest.entries)
    target_roots = {entry.target_root for entry in selected}
    roots = {}
    if "klipper" in target_roots:
        roots["klipper"] = canonical_root(klipper_root)
    if "config" in target_roots:
        roots["config"] = canonical_root(config_root)
    results = []
    for entry in selected:
        result = inspect_entry(entry, repo_root, roots)
        if (entry_id is not None and entry.owner == "vendor-managed" and
                result.get("code") == "VENDOR_MISSING"):
            repo = canonical_root(repo_root)
            root = roots[entry.target_root]
            result = _selected_missing_source_digest(entry, repo, roots, result)
        if result.get("code") == "VENDOR_COLLISION_FILE":
            repo = canonical_root(repo_root)
            root = roots[entry.target_root]
            code, fingerprints = _collision_fingerprints(
                entry, repo, root, Path(result["source"]), Path(result["target"]))
            result = dict(result)
            if code:
                result["code"] = code
            else:
                result.update(fingerprints)
        results.append(result)
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
