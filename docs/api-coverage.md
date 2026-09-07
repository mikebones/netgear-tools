# API coverage

What each device exposes, what this repo's clients use, and what Terraform
declares. Regenerate the counts with `python scripts/coverage.py` (add `--missing` to
list the uncovered route names).

The "declared in Terraform" column counts *resources*, not routes — one
resource often drives several routes, and the script's own per-route count
reads low for that reason.

The point of this page is the third column. A route that no client uses is
not a gap by itself — most of them are for features this network does not run.
A route that changes something **non-default** and is not declared anywhere is
the real gap, because that is what a factory reset or a replacement device
silently gets wrong.

## Summary

| Device | Routes exposed | Used by a client | Declared in Terraform |
| --- | --- | --- | --- |
| MS510TXUP | 358 | 29 | 10 resources |
| XS508TM | 275 | 18 | 3 resources |
| PR60X | 85 getters + 27 setters | 43 | 13 resources |
| WAX630E | 30 HTTP endpoints, 40 config subtrees | — | 7 resources |
| CM1000v2 | HTML pages only | 1 | none, by design |

Low percentages are expected and mostly fine. The switches expose the full
enterprise feature set — RADIUS, 802.1X, ACLs, LAGs, port mirroring, DiffServ,
routing — none of which this network uses.

## Where the route lists come from

- `scripts/xs508tm_routes.json` — 288 UI names mapped to `/api/v1/` paths.
- `scripts/ms510txup_endpoints.json` — 550 UI entries mapped to `cmd=` names,
  with the `get`/`set` verb.
- `scripts/discovery.json` — PR60X getters, swept live.
- `scripts/pr60x_setters.json` — PR60X setters, recovered from the UI bundle
  because the sweep only covered `get*`.
- WAX630E — from the firmware image itself. See
  [wax630e-http-api.md](wax630e-http-api.md).

**The setter list contains methods this firmware does not have.** `getSSH` and
`getFastPathEngine` are in the PR60X bundle and both answer
`rpc error -32601: Method not found` on firmware 3.0.0.105 — the bundle is
shared across models and releases. Probe before building on a name.

## Deliberate deviations from factory default

These are the settings that are *not* what the device ships with, so these are
the ones that must exist in Terraform. Everything else can be left undeclared:
a replacement device arrives at the default anyway.

| Device | Setting | Factory | Here | Consequence if lost |
| --- | --- | --- | --- | --- |
| WAX630E | `cloudStatus` | `1` | `0` | Insight **cloud management** re-enabled — configuration authority moves to NETGEAR |
| WAX630E | `timeZone` | `93` | `260` | Every syslog timestamp shifts |
| WAX630E | `ipAddr` / `dhcpClientStatus` | `192.168.0.100` / DHCP | static | AP leaves the subnet |
| WAX630E | `syslogStatus` + target | `0` / `0.0.0.0` | on, LAN collector | Logs stop, silently — the flag and address are stored independently |
| MS510TXUP | STP on the AP's port | on | **off** | Switch becomes crashable by the AP again |
| MS510TXUP | PoE priorities | all Low | Critical/High/Low | Cluster nodes shed first under budget pressure |
| PR60X | `rxCompensation` on `lan4`/`lan5` | mixed | `enhanced` | Receive errors on the SFP+ uplink |

## Known gaps

**MS510TXUP — per-port flow control.** `SetPortFlowControl` exists on the
client with no Terraform resource. Deliberately not built yet: flow control is
off and measured unnecessary here (a 3:1 oversubscription test that produced
33,000 TCP retransmits recorded **zero** receive overruns, so there is nothing
for PAUSE to signal). A resource would be a drift detector, not a fix.

**PR60X — the larger uncovered setters.** `setDualWanProfiles`,
`setLagSettings`, `setTrafficRules`, `setVlanAdvancedSettings`, `setVlanPorts`,
`setScheduledReboot`, `setDeviceName`, `setTimeSettings`. None are in use;
each would need its own read/verify cycle against the live router.

**XS508TM — most of 275 routes.** The three resources cover IGMP snooping,
port MTU and syslog. The rest is the enterprise feature set this network does
not run. Note this switch also has an **SSH CLI path** (`internal/xs508tm/cli.go`)
for settings the REST API does not expose.

**WAX630E — 33 of 40 config subtrees.** All at factory defaults and all for
features not in use: WDS, mesh, captive portal, 802.1X, the AP's own DHCP
server, IDS/IPS, MAC ACLs, walled garden. Confirmed at defaults by inspection:
`security:Url` and `mDNSSettings`. The rest were not individually verified —
the exact key names are in the factory-defaults baseline, and
`err_code 28` punishes guessing.

## Method

For any NETGEAR device here, in rough order of value:

1. **The firmware image**, if you can get it. `/etc/lighttpd.conf` (or the
   equivalent) is the authoritative endpoint list, and a factory `default-config`
   gives every setting name *and* the value a reset restores. See
   [wax630e-http-api.md](wax630e-http-api.md) for the UBI/squashfs extraction.
2. **The live UI bundle.** For the WAX630E this was verified byte-identical to
   the firmware's copy, so it is a faithful substitute when the image is not
   available. The switches and router serve theirs at `/static/js/main.<hash>.js`.
3. **The device's own update check.** `file_fwUpdateCheck` on the MS510TXUP
   returns the exact firmware filename, SHA-256 and release-notes URL for the
   current release.

Firmware for the MS510TXUP, XS508TM and PR60X was **not** obtainable this way:
the download paths under `downloads.netgear.com/files/GDC/` return 403 for
every filename pattern tried, including the exact name the switch itself
reports. The devices fetch firmware server-side and the UI bundles contain no
download base URL.
