# terraform-provider-pr60x

Terraform provider for the **NETGEAR PR60X** router, driving its local JSON-RPC
management API directly. No NETGEAR account, no Insight subscription, no cloud
dependency.

Built against firmware **2.7.0.111**. The full 238-method catalogue and
response shapes are in `scripts/schema.json`.

## Status

| Layer | State |
| --- | --- |
| Transport, auth, session handling | **Verified live** |
| `pr60x_device_info` data source | **Verified live** |
| `pr60x_service_profiles` data source | **Verified live** |
| `pr60x_port_forwarding_rules` data source | **Verified live** |
| `pr60x_vlan_profiles` data source | **Verified live** |
| `pr60x_dhcp_leases` data source | **Verified live** |
| `pr60x_wan_status` data source | **Verified live** |
| `pr60x_service_profile` resource | **Full CRUD verified live** through `terraform apply`/`destroy` |
| `pr60x_port_forwarding_rule` resource | add/delete verified live; edit follows the same confirmed contract |
| `pr60x_vlan_dhcp_dns` resource | **Verified live** — applied, imported, clean plan |
| `pr60x_static_route` resource | **Unverified** — field names inferred, see below |

Write shapes were confirmed by round trip against firmware 2.7.0.111 on
2026-08-31 (`scripts/roundtrip.py`, `scripts/roundtrip2.py`), and the full
create/update/delete lifecycle was then exercised through Terraform itself. The
port-forwarding probe was created with `enabled = 0` throughout, so no port was
ever actually opened during testing, and both tables were diffed against
snapshots afterwards.

`pr60x_static_route` is the exception: the device has zero static routes, so
there was no response to read field names from. They come from the web UI's
form. Create one throwaway route and confirm it reads back before relying on it.

## The protocol, briefly

Three details that are easy to get wrong, all of them load-bearing:

1. **`GET /` first.** It sets the `lhttpdsid` session cookie. Skip it and
   `login` fails with `-32602 invalid params`, which looks exactly like a wrong
   password but is a missing session.
2. **Auth is a `Security:` header, not the cookie and not `Authorization`.**
   `login` returns `result.token`; that token goes in `Security` on every later
   call. But the cookie is *also* still required — the token alone returns 401.
3. **Everything is one endpoint.** `POST /socketCommunication`, JSON-RPC 2.0.
   Every other path returns the SPA's `index.html` with HTTP 200, so probing for
   REST routes finds nothing but false positives.

The client serializes all calls behind a mutex with a 250 ms floor between them.
That is not paranoia: the device's backend config daemon degrades under load and
starts returning `HTTP 500 Failed to call process_configd_request. ret = -1` for
everything until it recovers. Terraform walks independent resources in parallel
by default, so without the lock a modest apply reproduces that reliably.

Two more quirks the client absorbs so callers do not have to:

**Writes are arrays of rows carrying their own id and an action.** A bare object
is rejected, and the *caller* allocates the id on create — the device stores
whatever id it is sent rather than assigning one:

```
add:    [ {...fields, "id": <next free>, "action": "add"} ]
edit:   [ {...fields, "id": <existing>,  "action": "edit"} ]
delete: [ <id>, ... ]
```

**Six methods double-wrap their payload** in a second `result` key —
`getVlanProfiles`, `getWanProfiles`, `getPortSettings`, `getVlanPorts`,
`getMacAclTable`, `getPasswordRecovery`. The other 57 do not. There is no
pattern; the set is enumerated from a full sweep and lives in `doubleWrapped`
in `client.go`. Re-run `scripts/discover.py` after a firmware upgrade to
re-check it.

## Usage

```hcl
terraform {
  required_providers {
    pr60x = { source = "local/mikebones/pr60x" }
  }
}

provider "pr60x" {}   # endpoint, username and password all have env fallbacks

data "pr60x_port_forwarding_rules" "all" {}

output "internet_exposed" {
  value = [for r in data.pr60x_port_forwarding_rules.all.rules : r if r.enabled]
}
```

| Setting | Attribute | Environment | Default |
| --- | --- | --- | --- |
| Endpoint | `endpoint` | `PR60X_ENDPOINT` | `https://192.168.1.1` |
| Username | `username` | `PR60X_USERNAME` | `admin` |
| Password | `password` | `PR60X_PASSWORD` | — (required) |
| Skip TLS verify | `insecure` | — | `true` (self-signed cert on a private IP) |

Prefer `PR60X_PASSWORD`. This is the only credential the device has and it owns
the network edge — it should come from Vault, not from a `.tf` file.

### A port forward is always two resources

The device has no "external port" field. A forwarding rule references *service
profiles by name* on both sides, and port translation is expressed by pointing
the two sides at different profiles: point `external_service` at an `SSH-ALT`
profile on port 2222 and `internal_service` at a plain `SSH` profile on 22, and
the device translates between them.

```hcl
resource "pr60x_service_profile" "wg_kube" {
  name       = "WG-KUBE"
  proto      = "udp"
  start_port = 51226
  end_port   = 51226
}

resource "pr60x_port_forwarding_rule" "wg_kube" {
  external_service = pr60x_service_profile.wg_kube.name
  internal_service = pr60x_service_profile.wg_kube.name
  dest_ip_address  = "192.168.1.72"
}
```

Reference `.name` rather than hardcoding the string, so Terraform orders the two
correctly. Deleting a profile that a rule still references is refused by the
provider rather than left to dangle.

## Importing what already exists

Nothing here was created by Terraform, so start by importing:

```bash
cd examples
PR60X_PASSWORD=... terraform plan          # lists current ids
terraform import pr60x_port_forwarding_rule.plex 0
terraform import pr60x_service_profile.plex 13
```

## Building

```bash
go build -o ~/.terraform.d/plugins/local/mikebones/pr60x/0.1.0/windows_amd64/terraform-provider-pr60x.exe .
cd examples && terraform init && PR60X_PASSWORD=... terraform plan
```

Adjust the OS/arch segment for other platforms. `terraform init` prints the
directory it actually searched if the path is wrong.

## scripts/

Python, stdlib only, no dependencies.

| Script | Purpose |
| --- | --- |
| `discover.py` | Calls every `get*` method, writes `discovery.json`. Read-only. |
| `collect.py` | Re-collects specific methods with gentle pacing when configd has been upset. |
| `roundtrip.py` | Confirms the service-profile add/delete payload shape. Mutating — snapshots first, cleans up, verifies. |
| `roundtrip2.py` | Confirms the edit shape and the port-forwarding add/delete shapes. Mutating; its probe rule is created `enabled=0` so nothing is ever exposed. |
| `set_dhcp_dns.py` | Sets DHCP option 6 for a VLAN, with `--show` and `--restore`. Snapshots, sends the profile back byte-for-byte with one field changed, and deep-diffs the result. |
| `schemagen.py` | Reduces `discovery.json` to the value-free `schema.json`. |
| `schema.json` | Committed schema reference: every method's response shape, no values. |

`discovery.json` is gitignored deliberately — it contains live DHCP lease
hostnames and MAC addresses plus the WAN public address. `schema.json` is the
committed equivalent.

### Fixing split DNS resolution

If private names resolve only some of the time, check what your DHCP server
advertises as option 6. Handing clients both a local resolver and a public one
gives them two nameservers with no rule for choosing, so anything only the
local resolver knows about fails roughly half the time — deterministically, but
looking for all the world like flaky networking.

```hcl
resource "pr60x_vlan_dhcp_dns" "lan" {
  vlan_id = 1
  servers = ["192.168.1.64"] # local resolver only
}
```

This resource adopts an existing VLAN and manages exactly one field. It will
not create or destroy VLANs, and it does not touch addressing, the DHCP range
or port membership. Changing option 6 cannot partition the network: it only
affects what future leases advertise, and existing clients keep their current
resolvers until they renew.

Import the current value first, so the first plan tells you what is really set:

```bash
terraform import pr60x_vlan_dhcp_dns.lan 1
```

## Auditing your own device

The read-only data sources are worth running even if you never manage anything
with this provider. `pr60x_port_forwarding_rules` is the authoritative answer to
"what is reachable from the internet?", which on most networks is recorded
nowhere outside the appliance itself. `pr60x_vlan_profiles` exposes each VLAN's
DHCP server state and its DHCP option 6 list, which is where surprising
split-DNS behaviour usually turns out to originate.

## Known gaps

- `pr60x_static_route` field names are unverified (above).
- `getStaticLeaseProfiles` takes `{"vlanID": 1}` — capital ID, and it returns
  `{"vlanID":…, "List":[…]}`. Confirmed working, currently empty, not yet wired
  into a resource.
- `getAttachedDevices` returns `-32603`, and `getCerts` / `getCertDetails`
  return `-32602` bare — all three take parameters not yet worked out.
- `getAppInstallState` / `getAppSettings` return `-32601`; those look
  unimplemented on this model rather than mis-called.
- VLAN profiles are deliberately read-only. Changing VLAN or DHCP settings can
  partition the network from the machine running the apply.
- `getWireGuardPeerProfiles` and `getWireGuardServerProfile` read cleanly, but
  were only ever observed against a device with the router's own WireGuard
  server disabled, so the populated shape is unknown.
- `getTrafficRules`, `getUpnpSettings`, `getSnmpSettings` and
  `getSecureDNSSettings` all read cleanly and are the next easy candidates;
  their schemas are already in `schema.json`.
- Dynamic, runtime-driven forwards (transmission peer ports, which change per
  pod restart) are a poor fit for Terraform. That case belongs in the gomission
  kopf operator, reusing this same protocol.
