# netgear-tools

Reverse-engineered clients, a Terraform provider and Prometheus exporters for
NETGEAR network hardware, driven entirely through each device's **local**
management API. No NETGEAR account, no Insight subscription, no cloud
dependency.

Four devices, four completely different protocols behind four different web
UIs. The one thing they all share is a `lhttpdsid` lighttpd session cookie.

```
internal/pr60x/       router client   - JSON-RPC 2.0 over one endpoint
internal/xs508tm/     switch client   - REST at /api/v1/
internal/wax630e/     AP client       - query-by-example over one endpoint
internal/ms510txup/   PoE switch client - signed CGI + RSA CSRF
internal/provider/    Terraform provider, built on the clients
cmd/pr60x-exporter/   Prometheus exporter for the router
cmd/xs508tm-exporter/ Prometheus exporter for the switch
scripts/              the Python used to reverse engineer each protocol
deploy/kubernetes/    exporter manifests
```

## Device coverage

| Device | Protocol | API mapped | Auth | Client | Exporter | Terraform |
| --- | --- | --- | --- | --- | --- | --- |
| **PR60X** router | JSON-RPC 2.0 | 238 methods | verified | yes | deployed | 7 resources |
| **XS508TM** switch | REST `/api/v1/` | 288 routes, 199 read | verified | yes | built | 2 resources |
| **MS510TXUP** switch | signed CGI + RSA CSRF | 550 endpoints, 234 read | verified | yes | — | 1 resource |
| **WAX630E** AP | query-by-example | 27 API entries + templates | verified | yes | — | 1 resource |

## The four protocols

### PR60X router — JSON-RPC 2.0

One endpoint, `POST /socketCommunication`. Three details are load-bearing:

1. **`GET /` first.** It sets the `lhttpdsid` cookie. Skip it and `login` fails
   with `-32602 invalid params`, which looks exactly like a wrong password.
2. **Auth is a `Security:` header** — not the cookie, not `Authorization`. But
   the cookie is *also* still required; the token alone returns 401.
3. Every other path returns the SPA's `index.html` with HTTP 200, so probing
   for REST routes finds only false positives.

Writes are arrays of rows carrying their own id and an `action`, and the
**caller allocates the id** — the device stores whatever it is sent:

```
add:    [ {...fields, "id": <next free>, "action": "add"} ]
edit:   [ {...fields, "id": <existing>,  "action": "edit"} ]
delete: [ <id>, ... ]
```

Six methods double-wrap their payload in a second `result` key; the other 57
do not. There is no pattern — the set is enumerated in `doubleWrapped` in
`client.go` from a full sweep.

### XS508TM switch — REST

A genuine REST surface, and easier to work with than the router:

```
POST /api/v1/login   {"login":{"username","password"}}
  -> {"resp":{"status","respCode","respMsg"}, "login":{"token","expire":86400}}
GET  /api/v1/<route>   Authorization: Bearer <token>
  -> {"resp":{...}, "<route_name>": <payload>}
```

Consistent `resp` envelope on every reply, so errors have a real channel. POST
bodies for list resources are **arrays** — a bare object returns `errCode 175`,
which is also what a duplicate returns.

Two firmware quirks the code absorbs so dashboards do not have to:

- **Counters are signed 32-bit and go negative** past 2^31. The live switch
  returns `octRx: -13233116` on its uplinks; the exporter unwraps them.
- **`linkup`/`linkstatus` cannot be trusted.** On this firmware they report 0
  for the two ports carrying all the traffic and 1 for six idle ones, verified
  against both traffic counters and LLDP. The exporter publishes the raw field
  as `port_reported_link_up` with a help string saying so, rather than silently
  "fixing" it.

### MS510TXUP switch — signed CGI behind an RSA CSRF token

**`sntpMode` is 0 for Unicast and 1 for Broadcast**, which is the opposite of
the obvious guess and fails silently. In broadcast mode the client waits for
NTP broadcasts and never transmits, so `reqs` stays 0 forever while the CLI
cheerfully reports `SNTP is Enabled` with a server configured. Setting it to 0
synced the clock within two poll cycles. The switch has no RTC, so it boots at
Dec 2022 every time and SNTP is the only thing standing between you and
three-year-old log timestamps.


Legacy jQuery/Backbone UI and by some distance the most defended of the four.
Four mechanisms, all reproduced in `scripts/ms510txup_login.py`:

- **Every URL is signed**: `&bj4=md5(<everything after the ?>)`, computed after
  the cache-busting `&dummy=<ms>` is appended. An unsigned request is a **400**.
- **The password is obfuscated**, never sent in clear. `encode()` builds a
  `320 - len(pw)` character string of random alphanumerics with the password's
  characters placed **in reverse at every 7th position**, and its length as a
  tens digit at index 123 and a ones digit at index 289.
- **Login is a handshake**: `POST cgi/set.cgi?cmd=home_loginAuth` returns an
  `authId`, then `home_loginStatus` is polled with it until it answers `ok`.
  It genuinely returns a non-ok status on the first poll.
- **`sess` is not a session token**, and this is the part that cost the most
  time. The UI base64-decodes it into three concatenated fields:

  ```
  tabid   = sess[0:32]     32-char session id
  expo    = sess[32:37]    RSA public exponent, always "10001"
  modulus = sess[37:]      1024-bit RSA modulus, hex
  ```

  It then **deletes** the `tabid` cookie it just set and authenticates every
  subsequent request with a header instead:

  ```
  X-CSRF-XSID: base64(RSA_PKCS1v15(tabid, pubkey))
  ```

  The padding is randomised, so the value is different on every request by
  design. Without the header the switch answers **404** — not 401, not 403 —
  which is indistinguishable from a wrong URL and is why this looked for a
  long time like an unfound endpoint rather than an unfound credential. The
  two gates are independent and checked in order: no signature is a 400, no
  CSRF header is a 404.

With all four in place, all 234 read commands are reachable. Confirmed live:
`home_sts` (per-port link, speed and PoE), `sys_info`, `lldp_neighbor`,
`log_remote`, `sys_dnsConf`.

Its SSH CLI works fully and is a viable alternative path, though config mode is
limited and has **no `logging` command at all** — which is exactly why syslog
needs the CGI API.

### WAX630E access point

Shares the router's transport - `POST /socketCommunication`, `lhttpdsid`
cookie - and almost nothing else.

**Login is not in the API map**, which is what makes it hard to find. The
bundle's 27-entry map has `logout` and `isloggedin` but no login, and the one
`/login` route in the whole bundle is `customerLogin` - the NETGEAR *cloud*
account modal, taking `{email,password}` from `#loginEmail`. The local admin
login is an ordinary query-by-example POST that carries a `time` header instead
of the usual `security` one:

```
POST /socketCommunication          time: <Date.toString(), +45min, "(Zone)" stripped>
  {"system":{"basicSettings":{"adminName":"admin","adminPasswd":"..."}}}
  -> {"status":0,...}              and the token in the `security` RESPONSE header
```

The web UI then stores `btoa(token)` in a **non-HttpOnly `ssid` cookie** and
sends `atob(cookie)` back as the `security` request header - so for a real
client the response header value *is* the request header value and the base64
round trip can be skipped entirely.

Everything after that is **query-by-example**: POST the JSON shape you want
with empty values and the device fills it in; the same shape with values set is
the write. There is no method name anywhere, and an invented shape is rejected,
so the templates in `client.go` are transcribed from the bundle rather than
guessed.

Two status codes look alike and are not:

- **`status: 100`** - not authenticated. The UI turns this into a bounce to
  `AP_login`. Every wrong guess at the login shape returns it, which is what
  made the login look unreachable for so long.
- **`status: 1, err_code: 28 "Invalid configuration"`** - authenticated fine,
  payload shape unrecognised.

Watch the lockout: more than two consecutive bad passwords disables login for a
firmware-chosen interval, returned as `err_code 26` with a `time` in minutes.
Probe the shape, not the password.

## Terraform provider

Each device family is configured separately and every one is optional — a
configuration that only manages the switch need not invent router credentials.

```hcl
terraform {
  required_providers { netgear = { source = "local/mikebones/netgear" } }
}

provider "netgear" {
  pr60x   = { endpoint = "https://192.168.1.1" }
  xs508tm   = { endpoint = "http://192.168.1.223" }
  wax630e   = { endpoint = "https://192.168.1.136" }
  ms510txup = { endpoint = "http://192.168.1.2" }
}
```

Passwords come from `PR60X_PASSWORD` / `XS508TM_PASSWORD` / `WAX630E_PASSWORD` /
`MS510TXUP_PASSWORD`. These devices have
no API-token concept, so that is the credential owning the hardware — source it
from a secret store, not a `.tf` file.

**The `required_providers` alias must match the resource prefix.** Leaving it
as `pr60x` while resources are `netgear_*` makes Terraform infer a second
provider and hunt for `registry.terraform.io/hashicorp/netgear`.

### Resources

| Resource | Notes |
| --- | --- |
| `netgear_pr60x_service_profile` | Named protocol/port definition. Full CRUD verified live. |
| `netgear_pr60x_port_forwarding_rule` | References service profiles **by name**. There is no external-port field, so port translation means pointing the two sides at different profiles. |
| `netgear_pr60x_vlan_dhcp_dns` | DHCP option 6 — the usual cause of split DNS. |
| `netgear_pr60x_remote_syslog` | Ships router logs to a UDP collector. |
| `netgear_pr60x_sqm` | Bufferbloat shaping. Rates must be 300 Kbps - 5 Gbps *even when disabled*; error 3103 means out of range. |
| `netgear_pr60x_upnp` | Exists mainly to be declared `false` and re-asserted. |
| `netgear_pr60x_static_route` | **Unverified** — field names inferred; the device has no routes to read back. |
| `netgear_xs508tm_igmp_snooping` | Ships off; multicast otherwise floods every port. |
| `netgear_xs508tm_syslog_server` | Also sets the global remote-logging flag, which ships disabled — a server entry alone does nothing. |

Data sources: `netgear_pr60x_device_info`, `_service_profiles`,
`_port_forwarding_rules`, `_vlan_profiles`, `_dhcp_leases`, `_wan_status`.

## Exporters

Both poll on their own schedule and serve a **cached snapshot** rather than
touching the device per scrape. This is not premature caution: the router's
config daemon wedges under rapid load, and the XS508TM's management web server
returns 502 and then refuses connections outright when driven at Terraform's
normal request rate. Neither affects the data plane — switching and routing
carried on throughout — but these are small embedded servers and they do fall
over.

So: **one replica each**, a 60s default poll, and the binaries refuse an
interval below 15s. The XS508TM client retries 502/503/504 and connection
resets with backoff.

Port counters are exposed as **gauges, not counters**: the devices zero them on
reboot with no reset signal, so Prometheus would read a reboot as a counter
reset and invent an enormous rate.

```bash
go build ./cmd/pr60x-exporter   && PR60X_PASSWORD=...   ./pr60x-exporter
go build ./cmd/xs508tm-exporter && XS508TM_PASSWORD=... ./xs508tm-exporter
```

Sample output:

```
pr60x_up 1
pr60x_management_mode{mode="local"} 1
pr60x_system_temperature_celsius 42
pr60x_firewall_connections 6400
pr60x_upnp_enabled 0

xs508tm_up 1
xs508tm_igmp_snooping_enabled 1
xs508tm_switch_rx_octets 4.286587466e+09
xs508tm_lldp_neighbor{local_port="9",remote_sysname="PR60X"} 1
```

### Deploying

`Dockerfile` builds a static binary on distroless; CI publishes multi-arch to
GHCR. `deploy/kubernetes/` carries Deployment, Service and ServiceMonitor.

Two things that cost time the first time:

- **`runAsNonRoot: true` needs an explicit `runAsUser`.** The distroless base
  declares `USER nonroot` by *name*, and kubelet will not verify a non-numeric
  user — it refuses with `CreateContainerConfigError`. Pin 65532.
- Multi-arch matters on a mixed cluster; a single-arch image simply fails to
  pull on the wrong node, with no obvious clue why.

## Building the provider

```bash
go build -o ~/.terraform.d/plugins/local/mikebones/netgear/0.1.0/<os>_<arch>/terraform-provider-netgear .
cd examples && terraform init && PR60X_PASSWORD=... terraform plan
```

`~/.terraformrc` (and `%APPDATA%/terraform.rc` on Windows) needs a
`filesystem_mirror` whose `include` covers `local/*/*`.

## scripts/

Python, stdlib only, no dependencies.

| Script | Purpose |
| --- | --- |
| `discover.py` | Sweeps every PR60X `get*` method. Read-only. |
| `collect.py` | Re-collects specific methods with gentle pacing after configd has been upset. |
| `roundtrip.py` / `roundtrip2.py` | Confirm the PR60X write shapes. Mutating — snapshot first, clean up, verify. |
| `set_dhcp_dns.py` | Sets DHCP option 6, with `--show` and `--restore`. |
| `schemagen.py` | Reduces a discovery dump to the value-free `schema.json`. |
| `xs508tm_discover.py` | Sweeps every XS508TM route safe to GET; refuses parameterised or state-changing ones. |
| `ms510txup_login.py` | Python reference for the MS510TXUP: URL signing, password obfuscation, the login handshake and the RSA CSRF header. Faster to iterate against than the Go client. Stdlib only - PKCS#1 v1.5 is implemented inline. |
| `*_routes.json`, `*_endpoints.json`, `wax630e_api.json` | The recovered API surfaces. |

Discovery dumps and device running-configs are **gitignored**: they carry LAN
inventory, WAN addresses and admin password hashes. `schema.json` is the
value-free equivalent that is safe to commit.

## Known gaps

- **The MS510TXUP emits malformed RFC5424 and nothing can parse it.** This is
  the one genuinely unsolved problem, and it is a firmware defect. On the wire:

  ```
  <15>1 2026-09-01T14:50:46.181-07:00: %192.168.1.2-1 SYSTEM-7-START_CONF_WRITE ...
                                     ^ stray colon        ^ stray %
  ```

  RFC5424 wants `TIMESTAMP SP HOSTNAME`; this is `TIMESTAMP: %HOSTNAME`, so a
  strict parser fails at column 36. Alloy reports `parsing error [col 36]` and
  drops every message. The device has no format option - `logging` is not a
  command in its CLI at all - so the fix has to be collector-side.
  `loki.source.syslog` has `syslog_format = "raw"`, which disables parsing and
  hands the line to `loki.process`, but it is experimental and needs Alloy's
  `stability.level` set to `experimental` process-wide.

  Note the counter lies: `log_remote.msgReceived` stays 0 while the switch is
  in fact transmitting. Trust `loki_source_syslog_parsing_errors_total` on the
  collector, or capture the datagrams, over anything this firmware reports
  about itself.
- **MS510TXUP DNS (`sys_dnsConf`) is not modelled yet** - still 8.8.8.8.
- **WAX630E reads beyond the transcribed templates.** Auth and the syslog and
  device-info shapes are verified live; the station and radio templates in the
  bundle are fragments of larger payloads and still return `err_code 28`.
- **The XS508TM management plane wedges and stays wedged** — lighttpd answering
  502 in ~10ms because the CGI backend behind it died. Only a management-plane
  restart clears it; retrying cannot. The data plane is unaffected throughout,
  so it is not an outage and does not justify an unplanned reboot.
- **MS510TXUP firmware cannot be upgraded through the CGI - use the web UI.**
  `scripts/ms510txup_firmware.py` gets most of the way and then does not
  finish. The image transfers, the switch parses and stores its metadata
  (`show bootvar` lists the right version, build date and filename),
  `file_http_downloadStatus` reaches `success`, and the boot selection really
  does move (`Not active*` on the CLI, not just the web UI's `nextAct`). The
  switch then boots the old image anyway and silently clears the selection.

  Ruled out, so nobody repeats them: it is not the version jump - 1.0.5.23,
  same series, fails identically to 1.1.1.9. It is not a corrupt payload - the
  multipart encoder round-trips a 12.3MB image byte-for-byte against a local
  server. What is left is that the upload CGI never commits the image as
  bootable, which fits it answering HTTP 404 on an otherwise "successful"
  upload. Finding the missing step means more reverse engineering next to a
  device that can be bricked, and the web UI does this in a few clicks.

  Dual-image is what makes the whole thing safe to have attempted: the running
  image is never written, so each failed attempt costs a reboot, not a switch.
- `netgear_pr60x_static_route` field names are unverified.
- PR60X `getAttachedDevices` returns `-32603`; `getCerts` / `getCertDetails`
  return `-32602`. All three take parameters not yet worked out.
- Jumbo frames are available (`jumbo-frame <1522-10000>` on the MS510TXUP), but
  MTU has to be changed end-to-end across switch, nodes and CNI together or it
  produces blackholes that affect only large packets.
