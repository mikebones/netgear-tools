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
| **MS510TXUP** switch | signed CGI | 550 endpoints | verified | partial | — | — |
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

### MS510TXUP switch — signed CGI

Legacy jQuery UI and the most defended of the four. Three mechanisms, all
reproduced in `scripts/ms510txup_login.py`:

- **Every URL is signed**: `&bj4=md5(<everything after the ?>)`. Unsigned
  requests are rejected.
- **The password is obfuscated**, never sent in clear. `encode()` builds a
  `320 - len(pw)` character string of random alphanumerics with the password's
  characters placed **in reverse at every 7th position**, and its length as a
  tens digit at index 123 and a ones digit at index 289.
- **Login is a handshake**: `POST cgi/set.cgi?cmd=home_loginAuth` returns an
  `authId`, then `home_loginStatus` is polled until it returns `ok` with a
  session token. It genuinely answers `Not Auth` on the first poll.

Login is **verified working** and authenticated *page* loads succeed.
Authenticated *CGI data* calls still return 404 — that gate has not been found,
and it is not the session cookie, a Referer, or XHR headers.
`scripts/ms510txup_endpoints.json` holds all 550 endpoints, including
`log_remoteAdd` (syslog) and `sys_dnsConf` (DNS).

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
  xs508tm = { endpoint = "http://192.168.1.223" }
  wax630e = { endpoint = "https://192.168.1.136" }
}
```

Passwords come from `PR60X_PASSWORD` / `XS508TM_PASSWORD` / `WAX630E_PASSWORD`. These devices have
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
| `ms510txup_login.py` | Ports the MS510TXUP's URL signing and password obfuscation. |
| `*_routes.json`, `*_endpoints.json`, `wax630e_api.json` | The recovered API surfaces. |

Discovery dumps and device running-configs are **gitignored**: they carry LAN
inventory, WAN addresses and admin password hashes. `schema.json` is the
value-free equivalent that is safe to commit.

## Known gaps

- **MS510TXUP CGI authorization** — login works, data calls 404. This is the
  blocker for its syslog, its DNS setting, and putting its config in Terraform.
- **WAX630E reads beyond the transcribed templates.** Auth and the syslog and
  device-info shapes are verified live; the station and radio templates in the
  bundle are fragments of larger payloads and still return `err_code 28`.
- **The XS508TM management plane wedges and stays wedged** — lighttpd answering
  502 in ~10ms because the CGI backend behind it died. Only a management-plane
  restart clears it; retrying cannot. The data plane is unaffected throughout,
  so it is not an outage and does not justify an unplanned reboot.
- `netgear_pr60x_static_route` field names are unverified.
- PR60X `getAttachedDevices` returns `-32603`; `getCerts` / `getCertDetails`
  return `-32602`. All three take parameters not yet worked out.
- Jumbo frames are available (`jumbo-frame <1522-10000>` on the MS510TXUP), but
  MTU has to be changed end-to-end across switch, nodes and CNI together or it
  produces blackholes that affect only large packets.
