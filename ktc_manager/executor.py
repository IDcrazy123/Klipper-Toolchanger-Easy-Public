import errno
import os
from pathlib import Path

from .inspector import canonical_root, inspect_entry, revalidate_source


def _item(entry_id, owner, code, action, target="", source="", error=None):
    result = {"id": entry_id, "owner": owner, "code": code, "action": action,
              "target": target, "source": source}
    if error is not None:
        result["errno"] = error
    return result


def _document(item, result):
    return {
        "schema_version": 1,
        "command": "apply",
        "profile": result,
        "dry_run": False,
        "result": item["action"],
        "summary": {
            "total": 1,
            "blockers": 0 if item["action"] in ("APPLIED", "NOOP") else 1,
            "created": 1 if item["action"] == "APPLIED" else 0,
            "noop": 1 if item["action"] == "NOOP" else 0,
        },
        "actions": [item],
    }


def _roots(klipper_root, config_root):
    return {"klipper": canonical_root(klipper_root), "config": canonical_root(config_root)}


def _errno_value(exc):
    value = getattr(exc, "errno", None)
    return value if isinstance(value, int) else None


def _blocked_for_syscall(entry, inspected, code, exc):
    return _item(entry.id, entry.owner, code, "BLOCKED", inspected.get("target", ""),
                 inspected.get("source", ""), _errno_value(exc))


def _post_apply(entry, repo_root, roots, preflight, syscall_error=None):
    try:
        post = inspect_entry(entry, repo_root, roots)
    except Exception:
        item = _item(entry.id, entry.owner, "APPLY_INDETERMINATE", "INDETERMINATE",
                     preflight.get("target", ""), preflight.get("source", ""),
                     _errno_value(syscall_error) if syscall_error is not None else None)
        return _document(item, ""), 20
    if syscall_error is not None and post["code"] == "VENDOR_MISSING":
        item = _item(entry.id, entry.owner, "APPLY_FAILED", "FAILED",
                     preflight.get("target", ""), preflight.get("source", ""), _errno_value(syscall_error))
        return _document(item, ""), 20
    if post["code"] == "VENDOR_OK":
        action = "APPLIED" if syscall_error is None else "INDETERMINATE"
        code = "VENDOR_OK" if action == "APPLIED" else "APPLY_INDETERMINATE"
        item = _item(entry.id, entry.owner, code, action,
                     post.get("target", preflight.get("target", "")),
                     post.get("source", preflight.get("source", "")),
                     _errno_value(syscall_error) if syscall_error is not None else None)
        return _document(item, ""), 0 if action == "APPLIED" else 20
    item = _item(entry.id, entry.owner, "APPLY_INDETERMINATE", "INDETERMINATE",
                 preflight.get("target", ""), preflight.get("source", ""),
                 _errno_value(syscall_error) if syscall_error is not None else None)
    return _document(item, ""), 20


def apply_entry(manifest, entry_id, repo_root, klipper_root, config_root):
    matches = [entry for entry in manifest.entries if entry.id == entry_id]
    roots = _roots(klipper_root, config_root)
    if not matches:
        item = _item(entry_id, "", "UNKNOWN_ID", "BLOCKED")
        return _document(item, manifest.profile), 10
    entry = matches[0]
    if entry.owner != "vendor-managed" or entry.delivery != "symlink":
        item = _item(entry.id, entry.owner, "PROTECTED_ENTRY", "BLOCKED", "", "")
        return _document(item, manifest.profile), 10

    inspected = inspect_entry(entry, repo_root, roots)
    if inspected["code"] == "VENDOR_OK":
        item = _item(entry.id, entry.owner, "VENDOR_OK", "NOOP",
                     inspected["target"], inspected.get("source", ""))
        return _document(item, manifest.profile), 0
    if inspected["code"] != "VENDOR_MISSING":
        item = _item(entry.id, entry.owner, inspected["code"], "BLOCKED",
                     inspected.get("target", ""), inspected.get("source", ""))
        return _document(item, manifest.profile), 10

    inspected = inspect_entry(entry, repo_root, roots)
    if inspected["code"] == "VENDOR_OK":
        item = _item(entry.id, entry.owner, "VENDOR_OK", "NOOP",
                     inspected["target"], inspected.get("source", ""))
        return _document(item, manifest.profile), 0
    if inspected["code"] != "VENDOR_MISSING":
        item = _item(entry.id, entry.owner, inspected["code"], "BLOCKED",
                     inspected.get("target", ""), inspected.get("source", ""))
        return _document(item, manifest.profile), 10

    target = Path(inspected["target"])
    source_code, source = revalidate_source(entry, repo_root)
    if source_code:
        item = _item(entry.id, entry.owner, source_code, "BLOCKED",
                     inspected["target"], source.as_posix())
        return _document(item, manifest.profile), 10
    # pathlib checks cannot eliminate TOCTOU races; the repo/source tree and target
    # roots/parents must be trusted user-owned paths with no concurrent updater while
    # this single syscall runs. This boundary does not claim to remove TOCTOU risk.
    try:
        os.symlink(str(source), str(target), target_is_directory=False)
    except (FileExistsError, PermissionError) as exc:
        code = "TARGET_EXISTS_RACE" if isinstance(exc, FileExistsError) else "PERMISSION_DENIED"
        item = _blocked_for_syscall(entry, inspected, code, exc)
        return _document(item, manifest.profile), 10
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if exc.errno in (errno.EACCES, errno.EPERM, errno.EEXIST) or winerror == 1314:
            code = "TARGET_EXISTS_RACE" if exc.errno == errno.EEXIST else "PERMISSION_DENIED"
            item = _blocked_for_syscall(entry, inspected, code, exc)
            return _document(item, manifest.profile), 10
        document, code = _post_apply(entry, repo_root, roots, inspected, exc)
        document["profile"] = manifest.profile
        return document, code

    document, code = _post_apply(entry, repo_root, roots, inspected)
    document["profile"] = manifest.profile
    return document, code
