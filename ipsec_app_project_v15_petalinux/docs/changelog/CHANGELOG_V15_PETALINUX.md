# v15 PetaLinux port

- Removed the runtime dependency on `systemctl`.
- `src/main.c` now requires `ipsec`, `swanctl`, `ip`, and `cat`.
- `src/strongswan.c` starts strongSwan with `ipsec start` when VICI is not ready.
- VICI readiness is verified with `swanctl --stats`, retried for up to 10 seconds.
- VICI socket diagnostics inspect both `/run` and `/var/run`.
- Sample configs use the swanctl compiled-default VICI URI unless explicitly set.
- `service_name` remains accepted only for backward-compatible config parsing.

The target PetaLinux rootfs must include strongSwan `swanctl` and the VICI plugin.
