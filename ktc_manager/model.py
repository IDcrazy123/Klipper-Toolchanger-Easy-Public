from dataclasses import dataclass
from pathlib import PurePosixPath
import hashlib
import json
import re
from pathlib import Path


class ManifestError(ValueError):
    pass


_DRIVE = re.compile(r"^[A-Za-z]:")
_WILDCARD = set("*?[]")
_WINDOWS_DEVICES = {
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *("com%d" % number for number in range(1, 10)),
    *("lpt%d" % number for number in range(1, 10)),
}
_TOP_KEYS = {"schema_version", "profile", "entries"}
_ENTRY_KEYS = {
    "vendor-managed": {"id", "owner", "source", "target_root", "target", "delivery"},
    "user-managed": {"id", "owner", "target_root", "target"},
    "machine-state": {"id", "owner", "target_root", "target"},
}


@dataclass(frozen=True)
class Entry:
    id: str
    owner: str
    target_root: str
    target: str
    source: str = ""
    delivery: str = ""


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    profile: str
    entries: tuple


def validate_relative_posix(value, field):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManifestError("%s must be a non-empty relative POSIX path" % field)
    if ("\\" in value or ":" in value or _DRIVE.match(value)
            or any(ch in _WILDCARD or ord(ch) < 32 or ch in '<>"|' for ch in value)):
        raise ManifestError("invalid %s path" % field)
    raw_parts = value.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise ManifestError("invalid %s path" % field)
    for part in raw_parts:
        if part.endswith((".", " ")):
            raise ManifestError("invalid %s path" % field)
        if part.casefold().split(".", 1)[0] in _WINDOWS_DEVICES:
            raise ManifestError("invalid %s path" % field)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ManifestError("invalid %s path" % field)
    return value


def _string(value, field):
    if not isinstance(value, str) or not value:
        raise ManifestError("%s must be a non-empty string" % field)
    return value


def parse_manifest_data(data):
    if not isinstance(data, dict) or set(data) != _TOP_KEYS:
        raise ManifestError("manifest must have exactly schema_version, profile, entries")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ManifestError("schema_version must be 1")
    profile = _string(data["profile"], "profile")
    if not isinstance(data["entries"], list):
        raise ManifestError("entries must be a list")
    entries = []
    ids = set()
    targets = {"klipper": set(), "config": set()}
    target_parts = {"klipper": [], "config": []}
    for raw in data["entries"]:
        if not isinstance(raw, dict):
            raise ManifestError("each entry must be an object")
        owner = raw.get("owner")
        if not isinstance(owner, str) or owner not in _ENTRY_KEYS or set(raw) != _ENTRY_KEYS[owner]:
            raise ManifestError("entry keys or owner are invalid")
        ident = _string(raw["id"], "entry id")
        folded_id = ident.casefold()
        if folded_id in ids:
            raise ManifestError("duplicate entry id")
        ids.add(folded_id)
        target_root = raw["target_root"]
        if target_root not in ("klipper", "config"):
            raise ManifestError("target_root must be klipper or config")
        target = validate_relative_posix(raw["target"], "target")
        folded_target = target.casefold()
        if folded_target in targets[target_root]:
            raise ManifestError("duplicate target")
        parts = tuple(part.casefold() for part in PurePosixPath(target).parts)
        if any(parts[: min(len(parts), len(other))] == other[: min(len(parts), len(other))]
               for other in target_parts[target_root]):
            raise ManifestError("overlapping target ownership")
        target_parts[target_root].append(parts)
        targets[target_root].add(folded_target)
        source = ""
        delivery = ""
        if owner == "vendor-managed":
            source = validate_relative_posix(raw["source"], "source")
            if raw["delivery"] != "symlink":
                raise ManifestError("vendor delivery must be symlink")
            delivery = raw["delivery"]
        entries.append(Entry(ident, owner, target_root, target, source, delivery))
    return Manifest(data["schema_version"], profile, tuple(entries))


def load_manifest(path):
    manifest, _digest = load_manifest_with_digest(path)
    return manifest


def load_manifest_with_digest(path):
    try:
        raw = Path(path).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError("cannot read manifest: %s" % exc)
    return parse_manifest_data(data), digest
