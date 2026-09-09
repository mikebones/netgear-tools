# netgear-tools

Reverse-engineered clients, a Terraform provider, a certificate operator and
Prometheus exporters for NETGEAR network hardware, driven entirely through each
device's **local** management interfaces. No NETGEAR account, no Insight
subscription, no cloud dependency.

The devices speak four completely different protocols behind four different web
UIs (the one thing they share is a `lhttpdsid` lighttpd session cookie), plus
one cable modem. On top of the clients sit three things that actually run:

- a **Terraform provider** (`netgear_*`) that manages device configuration;
- a **cert-operator** that installs cert-manager-renewed TLS certs onto the
  appliances, **root SSH/telnet first, web upload as automatic fallback**;
- one **Prometheus exporter per device**, several of which now read over a root
  shell so they hold **zero** web-management sessions.

> Addresses in this README are RFC 5737 documentation IPs (`192.0.2.0/24`) or
> `<placeholders>`. Supply real endpoints and credentials from the environment
> or a secret store — never commit them here.

```
internal/pr60x/       router client     - JSON-RPC 2.0 over one endpoint
internal/xs508tm/     switch client     - REST at /api/v1/ (+ root telnet push)
internal/wax630e/     AP client         - query-by-example over one endpoint
internal/ms510txup/   PoE switch client - signed CGI + RSA CSRF (+ root dropbear)
internal/cm1000/      cable-modem client - DOCSIS status scrape
internal/provider/    Terraform provider, built on the clients

cmd/cert-operator/    installs renewed TLS certs onto the appliances
cmd/pr60x-exporter/   Prometheus exporter for the router (root SSH; opt-in REST)
cmd/xs508tm-exporter/ Prometheus exporter for the switch (root telnet /proc; opt-in REST)
cmd/ms510txup-exporter/ Prometheus exporter for the PoE switch (root SSH; opt-in CGI)
cmd/wax630e-exporter/ Prometheus exporter for the access point (root SSH; opt-in REST)
cmd/cm1000-exporter/  Prometheus exporter for the cable modem

deploy/kubernetes/    a worked exporter manifest (PR60X) as a template
scripts/              the Python used to reverse engineer each protocol
```

## Device coverage

| Device | Protocol | Auth | Client | Exporter | Cert install | Terraform |
| --- | --- | --- | --- | --- | --- | --- |
| **PR60X** router | JSON-RPC 2.0 | `Security:` header + cookie | yes | yes | root SSH | yes |
| **XS508TM** switch | REST `/api/v1/` | Bearer token | yes | yes | root telnet, REST fallback | yes |
| **MS510TXUP** switch | signed CGI + RSA CSRF | obfuscated pw + `X-CSRF-XSID` | yes | yes | root dropbear, CGI fallback | yes |
| **WAX630E** AP | query-by-example | `time`/`security` headers | yes | yes | root SSH | yes |
| **CM1000v2** modem | HTML/JSON status | basic | yes | yes | — (ISP-provisioned) | — |

The four appliance protocols are documented in full below; the modem is a
read-only DOCSIS status scrape and has no management surface of its own.

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

- **Counters are signed 32-bit and go negative** past 2^31. A busy uplink
  returns e.g. `octRx: -13233116`; the exporter unwraps them.
- **`linkup`/`linkstatus` cannot be trusted.** On this firmware they report 0
  for the ports carrying all the traffic and 1 for idle ones, verified against
  both traffic counters and LLDP. The exporter publishes the raw field as
  `port_reported_link_up` with a help string saying so, rather than silently
  "fixing" it.

On the modified-firmware unit, a **root telnet shell** (`:2323`) is also
available — used by the cert-operator (primary install path) and, optionally,
by the exporter for management-plane health. It never touches the Broadcom diag
console; see the safety note under Exporters.

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
- **`sess` is not a session token**. The UI base64-decodes it into three
  concatenated fields:

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

  The padding is randomised, so the value differs on every request by design.
  Without the header the switch answers **404** — not 401, not 403 — which is
  indistinguishable from a wrong URL. The two gates are independent and checked
  in order: no signature is a 400, no CSRF header is a 404.

There is a **4-slot web session table**, shared by the UI, the exporter's
optional CGI path and Terraform. Fill it and the admin locks out. This is why
the exporter defaults to a root shell and the provider releases its session per
call (see below).

On the modified-firmware unit, **root dropbear** (`:2222`, user `sshd` → uid 0)
is the primary path for both the exporter and the cert-operator, and needs no
web session at all.

### WAX630E access point

Shares the router's transport — `POST /socketCommunication`, `lhttpdsid` cookie
— and almost nothing else.

**Login is not in the API map**. The bundle's 27-entry map has `logout` and
`isloggedin` but no login, and the one `/login` route is `customerLogin` — the
NETGEAR *cloud* account modal. The local admin login is an ordinary
query-by-example POST that carries a `time` header instead of the usual
`security` one:

```
POST /socketCommunication   time: <Date.toString(), +45min, "(Zone)" stripped>
  {"system":{"basicSettings":{"adminName":"admin","adminPasswd":"..."}}}
  -> {"status":0,...}   and the token in the `security` RESPONSE header
```

The web UI then stores `btoa(token)` in a **non-HttpOnly `ssid` cookie** and
sends `atob(cookie)` back as the `security` request header — so for a real
client the response header value *is* the request header value.

Everything after that is **query-by-example**: POST the JSON shape you want with
empty values and the device fills it in; the same shape with values set is the
write. An invented shape is rejected, so the templates in `client.go` are
transcribed from the bundle rather than guessed.

Two status codes look alike and are not:

- **`status: 100`** — not authenticated. Every wrong guess at the login shape
  returns it, which made the login look unreachable for so long.
- **`status: 1, err_code: 28 "Invalid configuration"`** — authenticated fine,
  payload shape unrecognised.

Watch the lockout: more than two consecutive bad passwords disables login for a
firmware-chosen interval (`err_code 26`, `time` in minutes). Probe the shape,
not the password. On the rooted unit, **root SSH** is the cert-operator's
install path.

## cert-operator — TLS cert renewal onto the appliances

cert-manager already issues and renews the appliance certificates as Kubernetes
TLS secrets. `cmd/cert-operator` closes the last-mile gap: getting the renewed
material onto boxes that have no idea cert-manager exists.

It is a poll loop, not an informer. Each cycle, for every managed device:

1. Read the target cert+key from the mounted TLS secret (`tls.crt`/`tls.key`).
2. TLS-dial the device on `:443` and read the leaf it currently **serves**;
   compare SHA-256 fingerprints against the target.
3. If they match, do nothing (idempotent, quiet). If they differ, push by the
   device's mechanism, then re-dial to confirm the new cert is live before
   recording success.

### SSH/root primary, web upload as automatic fallback

Every device now has a **root path as the primary installer**, with the older
web/API upload kept only as an automatic fallback that runs when the root path
is unreachable (dial/auth failure). Root is preferred because it needs no admin
web/management session — which is exactly what hits the switches' session limits
and lockouts. `firstWorking()` in `push.go` runs the primary and, only on error,
the fallback, logging which mechanism actually served the cert.

| Device | Primary (root) | Fallback (web) |
| --- | --- | --- |
| **PR60X** (`router`) | SSH: write `/etc/lighttpd/server.pem` + split key/cert, restart lighttpd | — |
| **XS508TM** (`sw2`) | telnet `:2323`: write the on-box cert files, reload lighttpd (no admin session, cannot be locked out) | REST upload (disable HTTPS → spool → verify → restore HTTPS) |
| **MS510TXUP** (`sw1`) | dropbear `:2222`: write `/mnt/ssh/*.pem`, rebuild the combined PEM, re-spawn lighttpd — **works even though sw1's admin is locked out** | HTTP CGI upload (`httprootcert.cgi` / `httpservercert.cgi`, then toggle HTTPS) |
| **WAX630E** (`wap1`) | SSH: write `/sysconfig/ssl/*`, rebuild `server.pem` + the `cert_generated` guard, copy to `/var/ssl`, re-spawn lighttpd | — |

The binary carries **no** device addresses, credentials or hostnames: every
per-device value comes from the environment (`ROUTER_HOST`, `SW1_HOST`,
`SW1_SSH_PORT`, `SW2_TELNET_ADDR`, `SW2_ENDPOINT`, `WAP1_HOST`, …) or a mounted
file (the TLS secrets, the switch admin password, the SSH private keys — the
`*_FILE` form is preferred for anything multi-line or secret). A device with no
env set is skipped; one listed but not yet wired is a quiet TODO stub.

```bash
go build ./cmd/cert-operator
# configured entirely from env / mounted secrets; see cmd/cert-operator/devices.go
POLL_INTERVAL=15m LISTEN=:9814 CERT_SECRET_NAMESPACE=netgear-certs ./cert-operator
```

Metrics (`netgear_cert_*`): `served_matches_target`, `notafter_seconds`,
`push_success_timestamp`, `push_errors_total`, `last_reconcile_timestamp`.

## rotate-admin — admin-password rotation that cannot lose the new password

`cmd/rotate-admin` rotates a device's admin password and keeps Vault and the
device from silently diverging — while making it **structurally impossible to
lose the freshly generated password**. It replaces an ad-hoc script that lost a
PR60X password to three bugs; each is designed out here:

- the script ran the rotation **twice** (the second run failed against the
  already-changed password) → the rotation is one straight line, called
  **exactly once**, with no loop and no retry of the device change;
- its Vault write was **gated on an exit code a later failing step clobbered**,
  so the write was skipped → the new password is written to Vault **first and
  unconditionally**, before the device is touched;
- a `grep -v` **hid the success line** so the operator misread the result → the
  outcome is a typed value mapped straight to an exit code, with **no output
  filtering** anywhere.

### Order of operations

1. **Read** the current secret from Vault (`secret/netgear/<device>`) — the old
   password (the device's change RPC needs it as input) and every other field.
2. **Generate** a strong password: guaranteed upper/lower/digit/symbol, and free
   of `:` and every shell/JSON metacharacter, so it is safe to paste and to hand
   to the device RPC unescaped.
3. **Write the new password to Vault FIRST**, before any device call, carrying
   the other fields through unchanged (merge/preserve). After this line succeeds
   the new password exists durably — a crash, panic, or kill below cannot lose
   it. The old value is held in memory for rollback.
4. **Change** the password on the device (`internal/pr60x.Client.SetAdminPassword`),
   **once**.
5. **Verify** with a *fresh* authenticated login using the new password.

### Failure handling and exit codes

The invariant: *Vault and the device never silently diverge, and the new
password is never lost.* Exit codes reflect the **actual device state**:

| Code | Meaning | Vault | Device |
| --- | --- | --- | --- |
| `0` | success, verified | new | new |
| `1` | precondition failure — nothing changed (bad flags/env, secret missing, **no current password in Vault**, generation or the first Vault write failed) | old | old |
| `2` | device change failed **cleanly**; Vault **rolled back** to old (the two agree, safe to re-run) | old | old |
| `3` | change RPC succeeded but **verify failed**; Vault **keeps** new — confirm the device manually | new | likely new |
| `4` | device change failed **and** the rollback failed — reconcile manually | new | old |

On a clean device failure (2) the device is provably still on the old password,
so rolling Vault back is safe. On a flaky verify (3) the device is very likely
already on the new password, so Vault *keeps* new — rolling back there would be
how you lose access. The password is **never printed** on any path.

### Requirements and usage

It needs the **current** password already in Vault (field `password`), because
the device's change RPC takes the old password as an argument. That is why it
**cannot fix the PR60X right now** — that password was lost — but it is correct
for every future rotation, and `xs508tm` / `wax630e` / `ms510txup` slot in by
adding a `Device` adapter (see `deviceFactories` in `device_pr60x.go`); the
`rotate()` core does not change.

```bash
go build ./cmd/rotate-admin
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=...                 # allowed to read + write the secret
# endpoint from env so no LAN IP is committed:
NETGEAR_ENDPOINT=https://198.51.100.1 ./rotate-admin -device pr60x
# flags: -device -endpoint -username -insecure -vault-path -mount -field -kv2 -length
```

One-shot CLI: it runs once and exits, starts no background work, and leaves no
lingering process. **Stop the pr60x exporter first** — it polls with the old
credential and will trip the router's failed-login lockout seconds after the
change (see `SetAdminPassword`'s doc comment).

## Exporters

Every exporter polls on its **own schedule** and serves a **cached snapshot**
rather than touching the device per scrape. This is not premature caution: the
router's config daemon wedges under rapid RPC load (~50 back-to-back reads), and
the XS508TM's management web server returns 502 and then refuses connections
when driven at Terraform's request rate. Neither affects the data plane, but
these are small embedded servers and they do fall over. So: **one replica each**,
a 60s default poll, and floors below which the binaries refuse to run.

Port counters are exposed as **gauges, not counters**: the devices zero them on
reboot with no reset signal, so Prometheus would otherwise read a reboot as a
counter reset and invent an enormous rate.

Every **rooted** device now defaults to its **least-session root path** (SSH or,
for the XS508TM, root telnet `/proc`) and keeps the old REST/API/CGI path as a
**config-gated fallback** — off unless a `*_ENABLE`/`*_ADDR` flag turns it on.
The only exception is the CM1000 cable modem, which has no root and stays
REST-only pending it.

| Exporter | Default port | Primary (default) transport | Config-gated fallback | Key env / flags |
| --- | --- | --- | --- | --- |
| `pr60x-exporter` | `:9812` | root SSH (ubus/`/proc`/`tc`/lsmod) | JSON-RPC (`PR60X_REST_ENABLE`) | `PR60X_SSH_ADDR`, `PR60X_SSH_KEY_FILE`; opt-in `PR60X_REST_ENABLE`+`PR60X_PASSWORD` |
| `xs508tm-exporter` | `:9813` | root telnet `/proc` health | REST switch stats (`XS508TM_REST_ENABLE`) | `XS508TM_TELNET_ADDR`, `XS508TM_TELNET_PASSWORD`; opt-in `XS508TM_REST_ENABLE`+`XS508TM_PASSWORD` |
| `ms510txup-exporter` | `:9814` | root SSH `/proc` | CGI/web-admin (`MS510TXUP_CGI_ENABLE`) | `MS510TXUP_SSH_ADDR`, `MS510TXUP_SSH_KEY_FILE`; opt-in `MS510TXUP_CGI_ENABLE` |
| `wax630e-exporter` | `:9815` | root SSH (`iw`/`/proc`) | query-by-example web API (`WAX630E_REST_ENABLE`) | `WAX630E_SSH_ADDR`, `WAX630E_SSH_KEY_FILE`; opt-in `WAX630E_REST_ENABLE`+`WAX630E_PASSWORD` |
| `cm1000-exporter` | `:9816` | HTML/JSON status (no root yet) | — | `CM1000_PASSWORD`; `--endpoint`, `--interval` |

Each SSH/telnet primary path **refuses to start without its `*_ADDR`** rather
than come up serving an empty `/metrics` that looks like a healthy device, and
exports a `*_ssh_up`/`*_telnet_up` gauge as the availability signal to alert on.
Every fallback **degrades gracefully**: a fallback that is off (or whose device
is unreachable) never affects the primary metrics. Both collectors on a device
share **one Prometheus registry**.

### The session-limit tradeoff (MS510TXUP)

`ms510txup-exporter` is **SSH-only by default and opens zero web sessions.** Its
primary and default data path is the dropbear root shell (`:2222`, ECDSA key
auth), reading the RealTek RTL93xx `/proc` tree — per-port byte/packet counters,
the `/proc/linkdown` reason ring (why and when a port bounced), `/proc/poe`,
SFP EEPROM, and VLAN membership. Everything it runs is a **passive read** of
`/proc`; it never writes a register, never enables a sampler, never touches the
CLI or SDK diag shell.

- **Required:** `MS510TXUP_SSH_ADDR` (`<switch-host>:2222`) and
  `MS510TXUP_SSH_KEY_FILE`. Optional `MS510TXUP_SSH_USER` (default `sshd`),
  `MS510TXUP_SSH_HOSTKEY`. Without the SSH address the exporter refuses to start
  rather than come up serving an empty `/metrics` that looks like a healthy
  switch. `ms510txup_ssh_up` is the availability signal to alert on.
- **Opt-in CGI fallback:** set `MS510TXUP_CGI_ENABLE=true` (plus
  `MS510TXUP_ENDPOINT` and `MS510TXUP_PASSWORD`, or the `--cgi` flag) to recover
  the metrics that are **not** in `/proc` — per-port link up/speed/duplex,
  error/collision counters, STP state, EEE. **Enabling it consumes ONE of the
  switch's four web session slots for the life of the process**, shared with the
  UI and Terraform, which is why it is off by default.

The old `--endpoint` / `--interval` flags and the default `MS510TXUP_PASSWORD`
requirement are **gone**: the SSH path uses `--ssh-interval` (floor 30s) and the
CGI path uses `--cgi-interval` (floor 15s), and the password is needed only when
CGI is enabled.

### SSH-primary (PR60X)

`pr60x-exporter` defaults to the router's **dropbear root shell** (key auth, no
password) and holds no web-admin session. One session per interval runs a fixed
**passive-read** batch: `ubus call network.interface.wan status` (WAN up/uptime),
`/proc/net/dev` (per-interface byte/packet/error/drop counters), the conntrack
count/max, `/proc/loadavg`, `/proc/meminfo`, `/proc/uptime`, `/sys/class/thermal`
(SoC die temps), `lsmod` (whether the Qualcomm `qca_nss_ecm`/PPE offload modules
are loaded — the modules that **bypass** the CAKE qdisc), and `tc -s qdisc show`
(CAKE/sqm sent/dropped/overlimits/backlog).

- **Required:** `PR60X_SSH_ADDR` (`<router-host>:22`) and `PR60X_SSH_KEY_FILE`.
  Optional `PR60X_SSH_USER` (default `root`), `PR60X_SSH_HOSTKEY`. `pr60x_ssh_up`
  is the availability signal.
- **Opt-in REST fallback:** `PR60X_REST_ENABLE=true` (plus `PR60X_PASSWORD`, or
  the `--rest` flag) recovers what SSH cannot: negotiated per-port link
  up/speed, the chassis fan RPM and API temperature sensor, and the
  security-posture flags (UPnP/DMZ/WAN-ping/secure-DNS/port-forwards). **Moving
  to SSH removes the exporter's dependence on the web-admin password** (which is
  being rotated separately), and its config daemon degrades under RPC load — so
  REST is off by default.

### SSH-primary (WAX630E)

`wax630e-exporter` defaults to the AP's **key-auth root shell**. One session per
interval runs `iw dev` (per-VAP channel/frequency/width/txpower, SSID, type),
`iw dev <vap> station dump` (**the per-client data the web API cannot provide** —
associated station count, per-station RSSI, tx/rx bitrates, connected time,
byte counters), `/proc/net/dev` (per-VAP traffic), and `/proc` CPU/memory/uptime.

- **Required:** `WAX630E_SSH_ADDR` (`<ap-host>:22`) and `WAX630E_SSH_KEY_FILE`.
  Optional `WAX630E_SSH_USER` (default `root`), `WAX630E_SSH_HOSTKEY`.
  `wax630e_ssh_up` is the availability signal.
- **Opt-in REST fallback:** `WAX630E_REST_ENABLE=true` (plus `WAX630E_PASSWORD`,
  or `--rest`) recovers the config/posture fields not on the shell — management
  VLAN, syslog enable/target, default-gateway-reachable, cloud/Insight-managed
  and DHCP-client flags. The AP has a **small session table** and a failed login
  leaks a slot (fills → the AP 401s the browser too), so the SSH path holding
  zero web sessions is the safe default.

### The management-shell collector (XS508TM) — SNMP assessment and a hard safety rule

`xs508tm-exporter` defaults to the switch's **root telnet `/proc` health
collector**, which holds **zero web sessions**: management-CPU load and memory,
the switching daemon's RSS/threads, and how full the config partition is. It runs
a **fixed set of passive reads only** (`cat /proc/*`, `df`).

It must never touch the Broadcom SDK diag console (`/sbin/devshell`,
`/tmp/consolepipe`, the diag socket on `127.0.0.1:2222`): doing so was measured
to starve the switching daemon's watchdog into a **hard switch reboot roughly
every 6 minutes**. Die temperature and other ASIC metrics are therefore
deliberately not collected here.

**Why switch stats still come over REST, not SNMP (the assessment):** the
port/vlan/igmp/LLDP counters are **not in `/proc`**, and the diag console that
carries them is off-limits, so the only session-free way to reach them is a
**read-only SNMP community** on udp/161. Enabling that community is a device-side
config change and is intentionally **not** performed by this metrics tooling — it
belongs in the switch's managed config, applied deliberately and reversibly. So
until an SNMP community exists, **the XS508TM cannot fully leave the web session
for switch stats**, and the REST collector is kept as the config-gated non-SSH
fallback:

- **Opt-in REST fallback:** `XS508TM_REST_ENABLE=true` (plus `XS508TM_PASSWORD`,
  or `--rest`) turns on the REST switch/port/vlan/igmp/LLDP stats. **It holds a
  web session, and a poll loop against the web login has re-locked the admin
  account before** — which is exactly why it is off by default. When SNMP is
  enabled, prefer it and leave REST off.

### Building and running

The rooted exporters are **SSH/telnet-primary by default**: point them at the
device's root shell, no web password needed unless the REST fallback is turned
on. `--endpoint`/`--interval` and the `*_PASSWORD` env now belong to the opt-in
fallback only.

```bash
# Rooted devices: least-session root path is the default.
go build ./cmd/pr60x-exporter
PR60X_SSH_ADDR=<router-host>:22  PR60X_SSH_KEY_FILE=/path/to/key  ./pr60x-exporter

go build ./cmd/wax630e-exporter
WAX630E_SSH_ADDR=<ap-host>:22    WAX630E_SSH_KEY_FILE=/path/to/key ./wax630e-exporter

go build ./cmd/ms510txup-exporter
MS510TXUP_SSH_ADDR=<switch-host>:2222 MS510TXUP_SSH_KEY_FILE=/path/to/key ./ms510txup-exporter

go build ./cmd/xs508tm-exporter
XS508TM_TELNET_ADDR=<switch-host>:2323 XS508TM_TELNET_PASSWORD=... ./xs508tm-exporter

# CM1000 has no root yet: REST-only.
go build ./cmd/cm1000-exporter   && CM1000_PASSWORD=... ./cm1000-exporter --endpoint "$CM1000_ENDPOINT"

# Turn on a fallback (example): PR60X REST for per-port link/speed + posture flags.
PR60X_SSH_ADDR=<router-host>:22 PR60X_SSH_KEY_FILE=/path/to/key \
  PR60X_REST_ENABLE=true PR60X_PASSWORD=... ./pr60x-exporter --endpoint "$PR60X_ENDPOINT"
```

Sample output:

```
pr60x_ssh_up 1
pr60x_wan_up 1
pr60x_nss_module_loaded{module="qca_nss_ecm"} 0
pr60x_qdisc_dropped_packets{interface="eth1"} 12
wax630e_ssh_up 1
wax630e_station_signal_dbm{interface="wlan0",station="de:ad:be:ef:00:01"} -55
xs508tm_telnet_up 1
ms510txup_ssh_up 1
ms510txup_proc_port_linkdown_reason_info{port="9",reason="HW-NoCableDetected"} 1
```

### Deploying

`Dockerfile` builds **one** exporter (or `cert-operator`) selected by the
`EXPORTER` build arg onto a distroless static base; the binary lands at a fixed
`/exporter` path so manifests differ only in image and args. CI
(`.github/workflows/exporter-image.yml`) tests, vets and publishes all six
multi-arch (`amd64`+`arm64`) to GHCR on push and on release.
`deploy/kubernetes/pr60x-exporter.yaml` is a worked template (Namespace,
Secret/Vault, Deployment, Service).

Two things that cost time the first time:

- **`runAsNonRoot: true` needs an explicit numeric `runAsUser`.** The distroless
  base declares `USER nonroot` by *name*; kubelet refuses a non-numeric user
  with `CreateContainerConfigError`. Pin 65532.
- Multi-arch matters on a mixed cluster; a single-arch image simply fails to
  pull on the wrong node, with no obvious clue why.

## Terraform provider

Each device family is configured separately and every one is optional — a
configuration that only manages the switch need not invent router credentials.
A device counts as configured when a password is found for it (block or env);
absence means "not managed here", not an error.

```hcl
terraform {
  required_providers { netgear = { source = "local/mikebones/netgear" } }
}

provider "netgear" {
  pr60x     = { endpoint = "https://192.0.2.1" }
  xs508tm   = { endpoint = "http://192.0.2.3" }
  wax630e   = { endpoint = "https://192.0.2.5" }
  ms510txup = { endpoint = "http://192.0.2.2" }
}
```

Passwords come from `PR60X_PASSWORD` / `XS508TM_PASSWORD` / `WAX630E_PASSWORD` /
`MS510TXUP_PASSWORD`. These devices have no API-token concept, so that is the
credential owning the hardware — source it from a secret store (e.g. Vault), not
a `.tf` file, so it never lands in state or version control.

**The `required_providers` name must match the resource prefix (`netgear`).**
Leaving it as e.g. `pr60x` while resources are `netgear_*` makes Terraform infer
a second provider and hunt for `registry.terraform.io/hashicorp/netgear`.

### Session handling

Terraform *kills* the provider process rather than shutting it down cleanly, and
these appliances free a management session only on explicit logout or an idle
timeout. Two mechanisms keep repeated plans from leaking sessions:

- **`main.go` calls `provider.Cleanup()` on every exit path** (not `defer`,
  because `log.Fatal` would skip it) to hand back any session still open.
- **The MS510TXUP client releases its session per call**
  (`SetReleasePerCall(true)` in `provider.go`). Its 4-slot table fills after a
  few plans inside the idle window otherwise, locking the admin out
  (`errCode 481`). The client's own mutex still keeps at most one login in
  flight per device, so this is safe under Terraform's default parallelism. The
  long-lived exporter, which shuts down cleanly, leaves this off and reuses its
  one session.

### Resources

The provider manages configuration on **all four appliances**. The authoritative
list is `Resources()` in `internal/provider/provider.go`; grouped:

- **PR60X** (`netgear_pr60x_*`): `service_profile`, `port_forwarding_rule`,
  `static_route`, `vlan_dhcp_dns`, `remote_syslog`, `sqm`, `upnp`,
  `static_leases`, `port_settings`, `management`, `time`.
- **XS508TM** (`netgear_switch_*` / `netgear_xs508tm_*`): `igmp_snooping`,
  `port_mtu`, `syslog_server`, `ssh`, `ip_routing`, `dhcp_relay`, `network`,
  `web_access`.
- **MS510TXUP** (`netgear_ms510_*`): `sntp`, `dns`, `syslog_server`, `vlan`,
  `igmp_snooping`, `igmp_querier_vlan`, `poe_port`, `stp_port`, `port_max_frame`,
  `web_access`.
- **WAX630E** (`netgear_ap_*` / `netgear_wax630e_*`): `network`, `syslog`,
  `radio`, `ssid`, `snmp`, `management`, `time`.

A few notes worth carrying forward:

- `netgear_pr60x_port_forwarding_rule` references service profiles **by name**;
  there is no external-port field, so port translation means pointing the two
  sides at different profiles.
- `netgear_pr60x_sqm` rates must be 300 Kbps – 5 Gbps *even when disabled*;
  error 3103 means out of range.
- `netgear_switch_syslog_server` (and its MS510 sibling) also sets the global
  remote-logging flag, which ships disabled — a server entry alone does nothing.
- `netgear_pr60x_static_route` field names are inferred, not verified live.

Data sources (PR60X): `netgear_pr60x_device_info`, `_service_profiles`,
`_port_forwarding_rules`, `_vlan_profiles`, `_dhcp_leases`, `_wan_status`.

### Building the provider

```bash
go build -o ~/.terraform.d/plugins/local/mikebones/netgear/0.1.0/<os>_<arch>/terraform-provider-netgear .
cd examples && terraform init && PR60X_PASSWORD=... terraform plan
```

`~/.terraformrc` (and `%APPDATA%/terraform.rc` on Windows) needs a
`filesystem_mirror` whose `include` covers `local/*/*`. `scripts/install_provider.sh`
automates the build-and-place step.

## scripts/

Python, stdlib only, no dependencies. The reverse-engineering harness each
client was built against, plus firmware tooling.

| Script | Purpose |
| --- | --- |
| `discover.py` / `collect.py` | Sweep / re-collect PR60X `get*` methods (read-only, gently paced). |
| `roundtrip.py` / `roundtrip2.py` | Confirm the PR60X write shapes. Mutating — snapshot first, clean up, verify. |
| `set_dhcp_dns.py` | Sets DHCP option 6, with `--show` and `--restore`. |
| `schemagen.py` / `coverage.py` | Reduce a discovery dump to the value-free `schema.json`; report API coverage. |
| `xs508tm_discover.py` | Sweeps every XS508TM route safe to GET; refuses parameterised or state-changing ones. |
| `ms510txup_login.py` | Python reference for the MS510TXUP: URL signing, password obfuscation, the login handshake and the RSA CSRF header. PKCS#1 v1.5 implemented inline. |
| `wax630e_client.py` | Query-by-example reference client for the AP. |
| `tftp_serve.py` | Read-only stdlib TFTP server — the MS510TXUP's HTTP firmware upload produces an unbootable image; TFTP does not. |
| `*_firmware.py` | Drive firmware upgrades per device (MS510TXUP over TFTP; others per device). |
| `ms510txup_poe_reset.py` | Power-cycle a PoE port. |
| `*_routes.json`, `*_endpoints.json`, `wax630e_api.json`, `schema.json` | The recovered API surfaces (value-free). |

Discovery dumps and device running-configs are **gitignored** (`.gitignore`):
they carry LAN inventory, WAN addresses and admin password hashes. `schema.json`
and the `*_routes/endpoints.json` files are the value-free equivalents that are
safe to commit.

## Known gaps

- **The MS510TXUP emits malformed RFC5424 syslog and strict parsers reject it.**
  It writes `TIMESTAMP: %HOSTNAME` where RFC5424 wants `TIMESTAMP SP HOSTNAME`,
  so Alloy fails at column 36 and drops every message. The device has no format
  option (`logging` is not a CLI command), so the fix is collector-side:
  `loki.source.syslog` with `syslog_format = "raw"` (experimental). The device's
  own `log_remote.msgReceived` counter lies (stays 0 while transmitting); trust
  the collector's `loki_source_syslog_parsing_errors_total`.
- **WAX630E station/radio reads beyond the transcribed templates** still return
  `err_code 28` — the bundle templates are fragments of larger payloads, so the
  exporter deliberately omits connected-station counts rather than silently
  reporting nothing.
- **The XS508TM management plane wedges and stays wedged** — lighttpd answering
  502 because the CGI backend died. Only a management-plane restart clears it;
  the data plane is unaffected, so it is not an outage.
- **MS510TXUP firmware: use TFTP, never the HTTP upload CGI.** Both transfer the
  image and report success; only TFTP produces one the switch will boot. Via the
  CGI the boot selection moves and then the loader silently reverts.
- **The MS510TXUP upgrade resets some configuration** (drops the remote syslog
  host, replaces SNTP with vendor defaults). Re-run Terraform after any upgrade.
- `netgear_pr60x_static_route` field names are unverified; PR60X
  `getAttachedDevices` / `getCerts` / `getCertDetails` take parameters not yet
  worked out.
- Jumbo frames are available (`jumbo-frame <1522-10000>` on the MS510TXUP), but
  MTU must be changed end-to-end across switch, nodes and CNI together or it
  blackholes only large packets.

## docs/

Protocol and recovery notes captured during reverse engineering:
`api-coverage.md`, `ms510txup-web-ui.md`, `wax630e-http-api.md`,
`xs508tm-recovery.md`, `recommendations.md`.
</content>
</invoke>
