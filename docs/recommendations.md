# Configuration recommendations

Findings from reading each appliance's firmware and live configuration.
Ordered by how much they matter, not by effort.

Nothing here is applied. Each entry says what it costs if it goes wrong,
because several of these touch a switch that supplies PoE to the whole
cluster.

---

## 1. Loop protection is off on both switches, and STP is off on one port

**This is the one that matters, and it is a gap we created.**

Spanning tree is disabled on MS510TXUP port 5. That was the right call — a
WAX630E on firmware older than 11.8.0.9 crashes the switch through STP, and
that switch powers all four cluster nodes, so making the switch immune was
worth more than waiting for the AP to behave.

But STP is also what detects a loop. Turning it off on a port removes the
only thing that would notice if something bridged that port back into the
network — a second cable, a misconfigured AP, a cheap switch plugged in later.
A broadcast storm on that port would take the network down and, because the
switch is the PoE source, the cluster with it.

Both switches ship loop protection **disabled**:

| Device | Setting | Now |
| --- | --- | --- |
| MS510TXUP | `loop_protect.admin` | `0` (per-port already armed: `act=1`, `status=1`) |
| XS508TM | `loopprotection_global_cfg.admin` | `0` (`txInterval=5`, `rxPdu=1`) |

Loop protection sends a probe frame and shuts the port if it sees its own
frame return. On an edge port with one host it is close to false-positive
free — which is exactly where port 5 sits.

**Risk of enabling:** a false positive disables a port. On ports 1–4 that
powers off a cluster node. Mitigate by enabling globally but confirming the
per-port action, and watch `loopCnt` before trusting it.

**DONE, 2026-09-07.** Global `admin=1`, `disableTimer=300`, and Keep Alive
enabled on **port 5 only** — the AP port, the one place STP is off. Every
other port still has STP, so it does not need this and does not get the
false-positive risk. Rx Action stays `Disable`; the 300s timer turns a false
positive into a five-minute blip rather than a dead port waiting for a human.

Verified via the API afterwards: `admin=1 disableTimer=300 port5 state=1`,
PoE undisturbed, 5/5 nodes Ready.

---

## 2. Storm control is completely off on the MS510TXUP

`storm_cfg` reports `glbState 0`, and every one of the ten ports `state 0`,
`threshold 0`.

This is the second half of the same problem. Loop protection catches a loop;
storm control caps the damage from a broadcast flood that is not a loop — a
misbehaving device, a broken NIC, an mDNS/SSDP storm.

**Recommendation:** enable broadcast storm control at a conservative
threshold on the edge ports. Do **not** set it aggressively on ports 1–4: the
cluster's own traffic includes legitimate multicast, and a threshold set too
low silently drops it.

---

## 3. Every DoS protection is off on both switches

`dos_cfg` (MS510TXUP) and `dos_service_cfg` (XS508TM) have every check
disabled, and `dos_auto` / `auto_dos_cfg` are off too.

Several of these are pure sanity checks on malformed frames with no
legitimate traffic that would trip them:

- `smacEqDmac` — source MAC equals destination MAC
- `sipEqDip` — source IP equals destination IP (Land attack)
- `pod` — ping of death (oversized ICMP)
- `smurf` — directed broadcast ICMP
- `tcpSynFin`, `tcpFinUrgPsh` — nonsensical TCP flag combinations
- `firstFrag`, `tcpFrag` — malformed fragments

**Recommendation:** enable the flag-combination and equality checks. Leave
`icmpv4`/`icmpv6` size limits and `tcpPort`/`udpPort` alone — those have real
false-positive potential.

**Value:** honestly modest on a LAN with no untrusted hosts. Worth it mainly
because the cost is zero and it is one fewer thing that is off because nobody
looked.

---

## 4. Switch management is over plain HTTP

`access_http` shows `admin 1`; `access_https` shows `admin 0` and
`present 0` — no certificate has been generated, so HTTPS is not actually
available. The exporter connects over plain HTTP, and so does every admin
session.

The admin password crosses the LAN in clear on every login.

**Recommendation:** generate a self-signed certificate (`access_httpsCert`)
and enable HTTPS. Then decide whether to disable HTTP — note the exporter's
endpoint has to change in the same commit, and a self-signed cert means the
client needs `insecure` set, which the clients already support.

**Caveat:** this is a LAN with no untrusted hosts on it. The realistic threat
is low. It is listed because it is cheap and because "the switch only speaks
HTTP" is worth knowing rather than discovering.

---

## 5. Session limits explain the lockouts

Not a recommendation so much as an answer, recorded because it cost real time
twice:

| Device | Setting | Value |
| --- | --- | --- |
| MS510TXUP | `access_http.maxSess` | **4** |
| MS510TXUP | `access_http.softTo` | 15 minutes idle |
| MS510TXUP | `access_http.hardTo` | 24 hours |
| WAX630E | `remoteSettings:inactivityTimeOut` | 300 seconds |
| PR60X | `getGuiIdleTimeout` | 45 minutes |

Four concurrent sessions on the MS510TXUP, freed only after 15 minutes idle.
Any tool that exits without logging out — anything calling `log.Fatal`, which
skips deferred calls — burns a slot for 15 minutes.

**Recommendation:** none for the devices. The fix is in the tooling, and is
already applied: return errors rather than `log.Fatal`, and always log out.

---

## 6. The AP and router take time from NETGEAR, over the WAN

| Device | NTP source |
| --- | --- |
| WAX630E | `time-b.netgear.com`, `customNtpServer 0` |
| PR60X | `time-b.netgear.com`, `time-c.netgear.com`, `customServerEnable 0` |

Both reach across the WAN for time. The router is the network's time
authority — the switches take SNTP from the LAN — so when the WAN is down,
the whole network's clocks drift together. That is precisely when the
timestamps matter.

**Recommendation:** point the AP at the LAN gateway, so it keeps
correct time whenever the LAN is up. Leaving the router itself on the vendor
pool is reasonable unless there is a local stratum source.

**Note the timezone codes are opaque and inconsistent between devices** — the
router calls this timezone `16`, the AP calls the same wall clock `260`.
Both are now declared in Terraform.

---

## 7. mDNS reflector is off on the router

`getMdnsSettings.enableReflector = 0`.

This closes out the earlier IGMP snooping work. Enabling IGMP snooping on the
switches bought nothing for service discovery, and this is why: mDNS is
link-local by design — 224.0.0.251 at TTL 1 — so it is never forwarded off
its VLAN and never snooped. The reflector is the setting that actually
governs cross-VLAN discovery.

**Recommendation:** leave off while everything that needs to discover each
other shares VLAN 1. Turn it on the day a device on the storage VLAN needs to
see a printer or a Chromecast on the main one. Now declared, so it is a
decision rather than a default.

---

## 8. Local-domain DNS forwarding is off on the router

`getVlanAdvancedSettings.enableLocalDomainDnsForwarding = 0`.

Worth investigating rather than acting on: this LAN runs its own resolver,
and how the router forwards local-domain queries interacts with that. Not
enough evidence yet to recommend a direction.

---

## Considered and rejected

**SNMP, on any device.** See [api-coverage.md](api-coverage.md) for what the
exporters already collect. SNMP's standard IF-MIB would duplicate metrics
that already exist with better labels and richer device-specific detail, and
its one unique capability — asynchronous traps — is already covered by syslog
shipping to the cluster's collector. Enabling it would add a listening
service, a second credential set to rotate, and on both the AP and the router
a set of factory-default community strings. The exporters win on every axis.

**Port security (`psecure_*`).** Off on the MS510TXUP, and correctly: pinning
MACs to ports breaks the moment a device is replaced or moved, in a way that
presents as a dead port rather than a policy decision.

**Flow control.** Measured unnecessary — a 3:1 oversubscription test that
produced 33,000 TCP retransmits recorded **zero** receive overruns, so there
is nothing for PAUSE to signal.

**Link aggregation and dual-WAN on the router.** Both off and both correct:
every device has a single uplink, and there is one WAN. Now asserted
read-only in Terraform so a silent change is visible — a dual-WAN failover
that turned itself on would send continuous probe traffic to public resolvers
and can flap the default route, which looks like an ISP fault rather than a
configuration one.
