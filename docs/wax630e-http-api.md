# WAX630E HTTP API

Reference for the WAX630E / WAX638E access point, firmware **V12.8.0.6**.

Everything here comes from the firmware image itself rather than from watching
the web UI, so it is the complete surface rather than the part the UI happens
to use. See [How this was derived](#how-this-was-derived) if you need to redo
it for a later release.

The endpoint list below is **byte-identical between V11.8.0.9 and V12.8.0.6**.
The HTTP surface has been stable across that range; what changed in 12.8.0.6 is
the vocabulary underneath `/socketCommunication` (SNMPv1/v2c is new).

## Authentication

`POST /login` establishes a session and returns a token. Two things trip people
up:

- **`GET /` first.** It issues the `lhttpdsid` cookie, and without it the login
  is rejected in a way that looks exactly like a bad password.
- **The timestamp is a JavaScript `Date.toString()` set 45 minutes ahead**, with
  the trailing `(Zone Name)` stripped. Reproduce it, do not rationalise it.

The token goes in a `security` header on every subsequent request.

### Sessions are a scarce resource

The AP caps concurrent logins and frees a slot only after a session has been
idle for `system:remoteSettings:inactivityTimeOut` seconds — **300 by default**.

Anything that exits without calling `/logout` burns a slot for that long. In Go
that means **`log.Fatal` is the hazard**: it skips deferred calls, so a
`defer c.Logout()` never runs and every failed run leaks a session. Enough of
those and every login is refused with `status 401`.

There is no way out through the API once that happens — `/reboot` needs a
session too. Recovery is cutting power. On a PoE deployment that is the switch's
job, not the AP's.

## Endpoints

Authoritative, from `/etc/lighttpd.conf` in the firmware rootfs. All are CGI
handlers in `/home/www/cgi-bin/`, all POST unless noted, and all take the
`security` header.

| Endpoint | Purpose |
| --- | --- |
| `/socketCommunication` | **Everything configuration.** See below. |
| `/login`, `/logout`, `/sessionCheck` | Session lifecycle. `/sessionCheck` takes `{"sessionCheck":""}` and answers `status 0` while the session is live. |
| `/hiddenLogin`, `/userName`, `/changeUserPassword`, `/forgotPassword` | Credentials. |
| `/reboot` | `{"reboot":1}`. Answers *before* going down. |
| `/HardFactory` | Factory reset. |
| `/getVersion`, `/APtype`, `/getBoardConfig` | Identity and model. |
| `/LogFile` | Overloaded by a numeric `method`. See below. |
| `/upgradeSFTP` | Firmware over SFTP. The route that actually works. |
| `/local_firmware`, `/file/firmwareupgrade` | Browser upload. Caps below the size of a real image. |
| `/swapfirmware` | Boot the other slot — the rollback. |
| `/restoreSettings` | Config restore. Multipart, with the archive password in a `password` header. |
| `/wa(....)-backup` | Config archive download. **A regex** — see below. |
| `/captivePortal`, `/cpUserInfo`, `/wifidog/*`, `/AutoRedirect` | Captive portal. |
| `/pCap_capture` | Packet capture. |
| `/aplog`, `/WAX6xx_Logs`, `/xagentlog`, `/wax6xx_xAgent_logs` | Log retrieval. |
| `/URL_TRACK` | Per-client URL logging. |
| `/collectiveAPI` | Cloud connectivity checks. Not a bulk config dump. |
| `/sampleMAC.txt`, `/getProductID.js` | Static (GET). |

### `/LogFile` — numeric methods

Not query-by-example. Takes a `method` integer:

| Method | Payload | Does |
| --- | --- | --- |
| 3 | `{"method":3,"password":"..."}` | Generate the config archive |
| 6 | `{"method":6,"fwPercent":N}` | Poll online-upgrade progress |
| 7 | `{"method":7,"fwUpgrade":0}` | Start the online upgrade |

**`fwPercent` is not a percentage.** 100 means the download finished; 110 is a
sentinel meaning the flash failed. Critically, **it describes the *online*
upgrade only** — nothing drives it during an SFTP upgrade, where it keeps
returning whatever the last online attempt left behind. Reading 110 during a
working SFTP upgrade and treating it as failure will abort a good flash. Ground
truth for SFTP is `sysVersion` once the AP answers again.

### The backup path is a regex

```
$HTTP["url"] =~ "/wa(....)-backup" {
    alias.url += ( "" => var.cgi-bin + "/wac5xx-backup" )
}
```

Any four characters match. `/wac510-backup` — the path the UI's own JavaScript
builds, inherited from the WAC510 — works on a WAX630E, and so would
`/wax630-backup`. There is one handler behind all of them.

Full backup flow:

```
POST /LogFile  {"method":3,"password":"..."}   ->  {"status":0}
GET  /wac510-backup                            ->  archive, name in Content-Disposition
```

The password encrypts the archive and is **required to restore**. An archive
whose password is lost is scrap.

## `/socketCommunication`

Query-by-example JSON. You send a skeleton of the reply you want with empty
strings as placeholders, and the AP fills it in. The same shape with values set
performs a write.

```jsonc
// read
{"system":{"timeSettings":{"timeZone":"","ntpAddr":""}}}
// write
{"system":{"timeSettings":{"timeZone":"260"}}}
```

### Rules that are not obvious

**Every value is a string**, including numbers and booleans. A JSON number is
rejected.

**The template must match the firmware exactly.** An unknown key, a wrong type,
or a key that exists on a different sibling all produce the same
`err_code 28: Invalid configuration`. The error does not say which mistake you
made, so change one thing at a time.

**The reply can nest deeper than the request.** `ssidGetDetails` is the trap:
you ask for `wlanSettingTable: {ssidGetDetails: ""}` and the reply puts the
SSIDs *inside* a key of that name. Treating the reply as the answer gives you a
single SSID literally named `ssidGetDetails`.

**Siblings are not interchangeable.** `wlan0` accepts `qamStatus`,
`loadBalancingStatus` and `maxClientLoadBalancingStatus`; `wlan1` does not, and
asking `wlan1` for them fails the *entire* query rather than omitting them.

**Read-modify-write, always.** Subtrees are shared between concerns —
`basicSettings` holds both the IP configuration and the cloud-management flag,
`remoteSettings` holds both SSH and the whole SNMP tree. Send only the fields
you mean to change.

### Configuration tree

Rooted at `system`. Counts are the number of leaf keys in the firmware's
factory defaults, which is a fair proxy for how much surface each area has.

| Subtree | Keys | What |
| --- | --- | --- |
| `vapSettings` | 3423 | Per-SSID settings, 8 VAPs × 3 radios |
| `wlanSettings` | 176 | Radios; also `ssidGetDetails` / `ssidSetDetails` |
| `wdsSettings` | 147 | Wireless bridging |
| `wmmSettings` | 116 | WMM/QoS queues |
| `dhcpsSettings` | 96 | DHCP server on the AP |
| `security` | 60 | URL filtering, domain blocklists |
| `basicSettings` | 56 | IP, cloud management, STP, day-zero, AP name |
| `mDNSSettings` | 51 | mDNS gateway and repeater policies |
| `info802dot1x` | 42 | 802.1X supplicant |
| `pktCaptureSettings` | 37 | Packet capture |
| `accessControlSettings` | 27 | MAC ACL groups |
| `remoteSettings` | 26 | SSH, Telnet, session timeout, SNMP |
| `ipsSettings` | 25 | IDS/IPS |
| `instantMeshSettings` | 17 | Mesh |
| `userSettings` | 13 | Local users |
| `timeSettings` | 7 | Timezone, NTP |
| `logSettings` | 6 | Syslog |
| `FwUpdate` | 5 | Update availability |

Plus ~20 smaller subtrees: `dhcpv6sSettings`, `staSettings`,
`walledGardenSettings`, `dhcpcSettings`, `idsIpsMailSettings`,
`dataVolumeLimit`, `firewallTable`, `fbSettings`, `wiredSettings`,
`instantWiFiSettings`, `gwlanSettings`, `httpRedirectSettings`, `apList`,
`configSettings`, `ensembleSettings`, `guiSettings`, `radioManagement`,
`captivePortalSettings`, `deviceModeTransition`, `l2Security`.

## Factory defaults worth knowing

These come from `/etc/default-config` in the firmware. They are what a reset or
a replacement device arrives with, which makes them the settings most worth
declaring somewhere.

| Setting | Factory | Why it matters |
| --- | --- | --- |
| `basicSettings:cloudStatus` | **`1`** | NETGEAR Insight cloud management **on**. A reset AP takes its configuration from the vendor cloud. |
| `basicSettings:dayZeroStatus` | `1` | Out-of-box wizard armed. |
| `basicSettings:ipAddr` | `192.168.0.100` | With `dhcpClientStatus 1`. Turning DHCP off without setting the statics moves the AP to a different subnet. |
| `basicSettings:priDnsAddr` | `8.8.8.8` | Public resolver; `sndDnsAddr` is `8.8.4.4`. |
| `timeSettings:timeZone` | `93` | Opaque table index. A reset silently shifts every syslog timestamp. |
| `timeSettings:ntpAddr` | `time-b.netgear.com` | The AP asks the vendor for time. |
| `remoteSettings:inactivityTimeOut` | `300` | Session slot lifetime — see [Sessions](#sessions-are-a-scarce-resource). |
| `remoteSettings:snmp:snmpV1V2c:status` | **`1`** | Armed even while the SNMP master switch is `0`, so it takes effect the moment SNMP is enabled. |
| `remoteSettings:snmp:...:readOnlyCommunity` | `snmpv1v2cuser` | Shipped community string. |
| `remoteSettings:snmp:snmpV3:authPassphrase` | `snmp1234` | Shipped, as is `privPassphrase`, under MD5 and DES. |
| `logSettings:syslogStatus` | `0` | Syslog off, and the target address is stored independently — so the AP can look configured while sending nothing. |
| radio `rateLimitStatus` | `1` @ 50 Mbps | **A real throughput cap, enabled from the factory on both radios.** |

## How this was derived

The web UI bundle is shipped inside the firmware, and the copy served by a live
AP is byte-identical to it — verified by SHA-256 against
`/home/www/dist/js/app.bundle.js` from the extracted V12.8.0.6 rootfs. So the
firmware image can be mined without touching a device.

The firmware `.tar` contains `nand-ipq5018-apps.img`, which is a **UBI image**,
not a plain filesystem. Carving the squashfs out of it by searching for the
`hsqs` magic produces a corrupt filesystem, because the data is interleaved
with 128 KB UBI erase-block headers. Reconstruct the volumes first:

```sh
pip install ubi_reader
ubireader_extract_images -o /tmp/ubi nand-ipq5018-apps.img
unsquashfs -d /tmp/root /tmp/ubi/*/​*vol-ubi_rootfs.ubifs
```

Then the three files worth reading:

- `/etc/lighttpd.conf` — the authoritative endpoint routing table.
- `/etc/default-config` — every setting name and its factory value, flat
  `system:group:key value` lines.
- `/home/www/dist/js/app.bundle.js` — payload shapes, since the request bodies
  are built at each call site rather than declared centrally.
