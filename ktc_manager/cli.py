import argparse
import json
import os
import sys
from pathlib import Path

from .executor import apply_entry
from .inspector import inspect, output_document, summary
from .model import ManifestError, load_manifest


HELP = "Read-only doctor, dry-run plan, and create-only single-entry apply for KTC-Easy."


def _parser():
    parser = argparse.ArgumentParser(prog="ktc_manager", description=HELP)
    sub = parser.add_subparsers(dest="command")
    for name in ("doctor", "plan", "apply"):
        child = sub.add_parser(name)
        child.add_argument("--manifest", default="manifests/ownership-v1.json")
        child.add_argument("--repo-root", default=None)
        child.add_argument("--klipper-root", default=None)
        child.add_argument("--config-root", default=None)
        child.add_argument("--format", choices=("text", "json"), default="text")
        if name == "plan":
            child.add_argument("--dry-run", action="store_true")
        if name == "apply":
            child.add_argument("--id", dest="ids", action="append")
    return parser


def _defaults(args):
    package_root = Path(__file__).resolve().parent.parent
    repo = Path(args.repo_root).expanduser() if args.repo_root else package_root
    klipper = Path(args.klipper_root).expanduser() if args.klipper_root else Path(os.environ.get("KLIPPER_PATH", "~/klipper")).expanduser()
    config = Path(args.config_root).expanduser() if args.config_root else Path(os.environ.get("CONFIG_PATH", "~/printer_data/config")).expanduser()
    manifest = Path(args.manifest).expanduser()
    if not manifest.is_absolute():
        manifest = repo / manifest
    return manifest, repo, klipper, config


def _text(document, command):
    profile = json.dumps(document["profile"], ensure_ascii=False, separators=(",", ":"))
    result = (" result=%s" % document["result"]) if command == "apply" else ""
    lines = ["KTCM1 %s profile=%s dry_run=%s%s" %
             (command, profile, str(document["dry_run"]).lower(), result)]
    values = document["results"] if command == "doctor" else document["actions"]
    for item in values:
        lines.append("KTCM1 item %s" % json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    s = document["summary"]
    lines.append("KTCM1 summary total=%d blockers=%d" % (s["total"], s["blockers"]))
    return "\n".join(lines)


def _usage_error(args, message):
    if getattr(args, "format", "text") == "json":
        print(json.dumps({"schema_version": 1, "error": message}, sort_keys=True))
    else:
        print("KTCM1 error %s" % message, file=sys.stderr)
    return 64


def main(argv=None):
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 64
    if args.command is None or (args.command == "plan" and not args.dry_run):
        return 64
    if args.command == "apply" and (args.ids is None or len(args.ids) != 1):
        return _usage_error(args, "apply requires exactly one --id")
    try:
        manifest_path, repo, klipper, config = _defaults(args)
        manifest = load_manifest(manifest_path)
        if args.command == "apply":
            document, exit_code = apply_entry(manifest, args.ids[0], repo, klipper, config)
        else:
            results = inspect(manifest, repo, klipper, config)
            document = output_document(args.command, manifest, results, args.command == "plan")
            exit_code = 10 if document["summary"]["blockers"] else 0
    except ManifestError as exc:
        if getattr(args, "format", "text") == "json":
            print(json.dumps({"schema_version": 1, "error": str(exc)}, sort_keys=True))
        else:
            print("KTCM1 error %s" % exc, file=sys.stderr)
        return 65
    except Exception as exc:
        if getattr(args, "format", "text") == "json":
            print(json.dumps({"schema_version": 1, "error": str(exc), "error_type": "internal"}, sort_keys=True))
        else:
            print("KTCM1 internal error %s" % exc, file=sys.stderr)
        return 70
    if args.format == "json":
        print(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(_text(document, args.command))
    return exit_code
