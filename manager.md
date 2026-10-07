# KTC-Easy Manager Safety Guide

The KTC-Easy manager is a state inspector with one narrowly scoped create-only operation. It is not a complete installer and it does not provide automatic migration for existing regular-file layouts.

## Ownership model

- `vendor-managed` entries are inspected by `doctor` and `plan`. `apply` may create one missing vendor symlink when the target parent already exists.
- `user-managed` and `machine-state` entries are preserve-only. `doctor` and `plan` report their status; `apply` blocks them and does not hash, copy, replace, or delete their contents.

## Commands

```text
python3 -B -m ktc_manager doctor [--profile ALIAS] [--id ID] [--format text|json]
python3 -B -m ktc_manager plan --dry-run [--profile ALIAS] [--id ID] [--format text|json]
python3 -B -m ktc_manager apply [--profile ALIAS] --id ID --expect-profile PROFILE --expect-manifest-sha256 SHA256 [--format text|json]
```

`ID` matching is exact and case-sensitive. Without `--id`, `doctor` and `plan` retain their all-entry behavior. A selected command returns exactly one item/action. Repeating `--id` is a usage error. `plan` always requires `--dry-run`; `apply` requires exactly one ID.

`doctor` and `plan` report `manifest_sha256`, the lowercase SHA-256 of the exact manifest file bytes used. `apply` requires exactly one `--expect-profile PROFILE` and one `--expect-manifest-sha256 SHA256`. Copy both values from the earlier output and reuse the same manifest selector (`--profile` alias or `--manifest` path). A profile mismatch or raw-byte digest mismatch returns exit 65 before apply execution. The digest binds the manifest bytes, but does not confirm source/target state or a Git commit and does not eliminate all TOCTOU risk.

The optional `--profile` aliases select built-in manifests relative to `--repo-root`: `cartographer` selects `manifests/ownership-v1.json` and profile `voron-5-tool-cartographer`; `tap-per-tool` selects `manifests/ownership-v1-tap-per-tool.json` and profile `voron-5-tool-tap-per-tool`. With no alias, the default remains the Cartographer manifest. `--profile` and an explicit `--manifest` are mutually exclusive; a custom manifest continues to work when `--profile` is omitted. Aliases do not detect or validate hardware.

The commands use the repository manifest and configured repository, Klipper, and printer-config roots. Use `--format json` for machine-readable output; text output uses the `KTCM1` protocol prefix. Output is deterministic and contains no ANSI formatting.

## Optional TAP profile

TAP users must opt in explicitly with `--profile tap-per-tool` or by passing `--manifest manifests/ownership-v1-tap-per-tool.json` to `doctor`, `plan`, or `apply`. This TAP profile is not the default. Before any `apply`, verify that the emitted document's `profile` is exactly `voron-5-tool-tap-per-tool` and pass that exact value as `--expect-profile`.

The TAP profile is identical to the default `voron-5-tool-cartographer` profile except for exactly two differences:

- `vendor-toolchanger-include` uses `examples/easy-additions/user-configs/toolchanger-include.cfg` instead of the Cartographer scanner include.
- It adds the vendor-managed `vendor-tool-detection` symlink from `examples/easy-additions/tool_detection.cfg` to `toolchanger/readonly-configs/tool_detection.cfg`.

## State and action meanings

| Inspection state | Doctor / plan meaning | Apply meaning |
| --- | --- | --- |
| `VENDOR_OK` | Existing correct symlink / `NOOP` | `NOOP`, exit 0 |
| `VENDOR_MISSING` | `WOULD_LINK` | A create-only symlink may be made only when the target parent already exists; apply does not create parents |
| `VENDOR_COLLISION_FILE` | `BLOCKED`, even for `IDENTICAL_BYTES` | Blocked; collision fingerprints are informational, not authorization |
| `VENDOR_COLLISION_DIRECTORY` or other collision | `BLOCKED` | Blocked |
| `VENDOR_WRONG_LINK` or `VENDOR_BROKEN_LINK` | `BLOCKED` | Blocked |
| Protected entry | Preserve or preserve-missing; no fingerprints | Blocked; contents are not replaced or copied |
| Missing parent, root escape, reparse/symlink structure, unreadable input, or detected race | `BLOCKED` | Blocked; apply may report failed/indeterminate syscall outcomes |
| Unknown ID | `UNKNOWN_ID`, `BLOCKED` | Apply returns a blocked document with `UNKNOWN_ID`, performs no symlink creation or other filesystem mutation, and exits 10 |

Doctor and plan collision results may include raw-byte SHA-256 values for source and target plus `content_relation`. The relation distinguishes identical bytes, equality after only CRLF normalization, and different bytes. Fingerprints can become stale and never authorize a write or legacy installer run.

## Exit codes

- `0`: no blocker, or a successful/no-op apply.
- `10`: domain or filesystem blocker, including an unknown ID.
- `20`: apply failed or became indeterminate after an attempted syscall.
- `64`: CLI usage, selector cardinality, invalid `--expect-manifest-sha256`, or missing `plan --dry-run`.
- `65`: invalid or unreadable manifest, or `--expect-profile` / manifest digest mismatch.
- `70`: unexpected internal error.

## Safety boundaries

`doctor` and `plan` are read-only. `apply` accepts one vendor-managed ID and only creates a symlink at a currently missing target with an existing parent. It does not create directories, replace regular-file collisions, copy protected configuration, create backups, migrate an old layout, or restart a service. There is no supported automatic collision migration.

The manager trusts the repository/source tree and target roots/parents as user-owned paths and assumes no concurrent updater while a check is running. This is an operational assumption; it does not claim to eliminate TOCTOU risk against an actor mutating those paths.

`install.sh` is a separate legacy mechanism with different and broader behavior. Do not treat manager fingerprints or a clean inspection as authorization to run it.

## Collision workflow — STOP / REVIEW REQUIRED

When a target is a regular-file collision:

1. Run `doctor --id ID`.
2. Run `plan --dry-run --id ID`.
3. Review the exact target/source hashes and `content_relation`.
4. Keep the target unchanged and obtain an explicit, separately reviewed migration procedure.

Do not use these results as permission to remove, move, force-link, replace, or restore files. Old-layout migration is HOLD/unsupported by the manager.
