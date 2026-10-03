## Upgrade from the old Klipper-Toolchanger-Easy

Start with the [KTC-Easy Manager Safety Guide](manager.md). The manager can inspect existing symlink installs and can create one missing vendor symlink when its parent already exists. It does not migrate an existing regular-file layout.

`install.sh` is legacy and outside the manager guarantees. It uses force-link operations, creates directories, copies files, and restarts Klipper. Do not treat repeated legacy installer runs as safe or idempotent, and do not use doctor/plan fingerprints as authorization to run it.

If inspection reports a regular-file collision, follow the manager's `STOP / REVIEW REQUIRED` workflow and keep the target unchanged. There is no supported automatic migration procedure here.

For a separately reviewed upgrade, inventory and compare these historical layout considerations:

- compare tools in `stealthchanger/tools` with the user-managed `toolchanger/tools` destination
- compare changes in `stealthchanger/toolchanger-config.cfg` with the user-managed `toolchanger/toolchanger-config.cfg` destination
- review tool fan declarations such as `fan: fan_generic Tx_partfan` versus `fan: Tx_partfan`
- review the printer include `[include stealthchanger/toolchanger-include.cfg]` versus `[include toolchanger/readonly-configs/toolchanger-include.cfg]`
- inventory additional includes from the old toolchanger configuration for an explicitly approved merge

Preserve existing destination and user-managed files during this review. Copying, merging, replacement, and legacy cleanup are outside the manager workflow and require a separately reviewed procedure.
