# XS508TM: recovering when the web interface is gone

Written after taking a switch's management interface down with a certificate
upload on 2026-09-07, and recovering it fully the same day. Everything here was
learned in that incident. The headline correction to the first draft: **this is
recoverable, and cleanly.** A broken web certificate is not a dead switch.

## First: a dead web UI is not an outage

The web UI on this switch is **lighttpd**, a userspace app. It is not the
switch. Separate them before doing anything drastic:

```
ping <switch>                 # data plane and management IP
nmap -Pn -p 1-1024 <switch>   # what is still listening
kubectl get nodes             # is anything downstream actually affected
```

In the incident the switch forwarded perfectly throughout - all cluster nodes
Ready, all Longhorn volumes healthy - across every reboot and the factory
reset. Only ports 80/443 were ever gone. Treat a dead web UI as a service
problem, not a network emergency.

## What actually breaks it

lighttpd refuses to start if HTTPS is enabled and its certificate file is
missing:

```
RestAgent: Failed to start lighttpd ... libcrypto.so.3: no version information
(fdevent.c) fdevent_load_file() /mnt/fastpath/lighttpd/ssl/https_cert.cer: No such file or directory
```

Once it dies it takes BOTH listeners with it - HTTP and HTTPS - because it
aborts before binding either. `application stop/start lighttpdMon` and a full
`reload` do not help: the certificate lives on flash, survives a reboot, and
RestAgent does not regenerate it on boot.

### The CLI cannot repair the certificate, and that is fine

There is no `crypto`/`certificate`/`ssl` command in any CLI mode; `ip http`
offers only accounting and authentication; and `copy <url>` installs ca-root,
client-ssl-cert, root-ca-certs and SSH keys but has **no destination for the
web server's own certificate**. `nvram:script` only replays CLI commands, which
have no file-write verb. So you cannot put the missing file back from the CLI.

You do not need to. **A factory reset fixes it** - see below.

## The fix: factory reset restores a working state

The broken state is `httpsEnable=1` with the certificate file gone. The
**factory-default** state is `httpsEnable=0` (plain HTTP, which is also what the
exporter uses) with a self-signed certificate present. So restoring factory
defaults returns lighttpd to a state it can actually start in:

```
enable
clear config          # answer y - this reboots the switch
```

`clear config` is all-or-nothing and **drops the management IP and the admin
password**. That is the whole cost, and the rest of this playbook is paying it
back. Have a plan for the IP (below) before you run it.

## Post-reset recovery, in order

### 1. Find the switch

Factory default is **DHCP client**. The switch reboots and takes a lease from
whatever serves DHCP. Find it by its burned-in MAC in the router's lease table
(`getDhcpLeases`). The web UI is back on **HTTP :80** at that address the moment
lighttpd starts.

### 2. Log in and change the password

Factory login is `admin` / `password`, and the API login reply carries
`def_password:1`. The switch forces a change on first use. Change it back to the
managed value so existing tooling keeps working - over SSH once it is enabled
(step 3), or through the UI. The def-password change replies "Log in again
using the new password" rather than "Password Changed"; that is success, not
failure.

### 3. Enable SSH

Factory default is SSH **off**. Turn it on early - it is the second way in when
the web plane is wedged. `ssh_global_cfg` `admin=1` over the API (verified: port
22 begins listening), or `ip ssh server enable` from the CLI.

### 4. Restore the static IP - and the trap that lives here

If the address should be static, this is the step that will strand you if you
are not careful:

```
network protocol none        # "will reset ip configuration" - answer y
network parms <ip> <mask> <gw>
```

**`network protocol none` resets the IPv4 config immediately** and drops the
switch onto its default static address (192.168.0.239), on a different subnet.
Your SSH session dies at the `y`, before `network parms` is sent, and now the
switch is unreachable over IPv4 from your LAN.

**The way back in is IPv6 link-local.** The switch's `fe80::` address is derived
from its MAC and is completely independent of the IPv4 configuration, so it
survives the reset. From a host on the same L2 segment:

```
# derive/observe the address (show network prints it as "IPv6 Prefix is fe80::...")
# find which local interface reaches it:
ping fe80::<switch-eui64>%<zoneN>       # try each interface's zone id
ssh admin@[fe80::<switch-eui64>%<zoneN>]
network parms <ip> <mask> <gw>          # session SURVIVES - link-local is unaffected
write memory
```

Setting the IPv4 address over link-local does not drop the link-local session,
so you can set the final static IP and confirm it in one connection. This is the
single most useful fact in this document.

### 5. Reapply the rest of the configuration

A factory reset wipes everything. Reapply the Terraform-managed subset
(`terraform apply` - igmp snooping, syslog, port MTU, web access), then restore
anything not yet in Terraform from the captured baseline (on this network:
`ip routing`, `ip helper enable`, `ip helper-address <relay> dhcp`). `write
memory` after CLI changes, or they revert on reboot.

## Gotchas worth knowing

* **Syslog writes need the envelope.** `server_log_cfg` accepts the enveloped
  object `{"server_log_cfg":[...]}` and rejects a bare array with errCode 175
  ("Log configuration failed"). Same shape a GET returns. (Fixed in the
  provider's syslog resource.)
* **HTTP session slots are scarce.** maxSes is 4 and the softTimeout is 15
  minutes. A tool that logs in without logging out burns a slot for the full
  timeout; a handful of those and login returns errCode 481 ("Maximum allowed
  sessions reached"). SSH is a separate path and is unaffected - lean on it.
* **TFTP export is broken on this firmware.** Exports of crash-log, errorlog,
  operational-log and startup-config all arrive 0 bytes. Capture the running
  config off the terminal (`show running-config`) instead.

## Installing a trusted certificate (the safe way)

The install that started all this can be done safely - the killer was doing it
with HTTPS enabled. On 2026-09-07 a Let's Encrypt cert was installed on sw2 and
validates cleanly (issuer Let's Encrypt, no browser warning). The one rule that
makes it safe: **disable HTTPS first**, so the transient cert/key mismatch
mid-install cannot trigger the lighttpd reload that kills it.

Through the UI (System > Protocols > HTTP), in order:

1. Toggle **Allow HTTPS off**, Apply. lighttpd now serves HTTP only.
2. Certificate Upload, File Type **X.509 Public Certificate PEM**, upload the
   leaf+chain PEM, Apply. Certificate Present flips to No (expected: cert
   replaced, key not yet matching).
3. File Type **X.509 Certificate Private Key PEM**, upload the key, Apply.
   Certificate Present returns to Yes.
4. Toggle **Allow HTTPS on**, Apply. It now serves the trusted cert.

The cert must match the name the browser uses (CN/SAN sw2.<domain>, which must
resolve to the switch), and the PEM should carry the intermediate chain so a
browser can build the path.

### The request recipe (for automating renewal)

Captured from the UI. Each file is two requests; four in all:

	POST /cgi/v1/file_upload      multipart, field "file"   -> spools to /tmp/lighttpd/upload.tmp
	POST /api/v1/https_cert_upld  {"https_cert_upld":{"file":1,"localpath":"/tmp/lighttpd/upload.tmp"}}
	POST /cgi/v1/file_upload      (the key)
	POST /api/v1/https_cert_upld  {"https_cert_upld":{"file":2,"localpath":"/tmp/lighttpd/upload.tmp"}}

`file` is 1 for the certificate, 2 for the key. **Headless reproduction is not
solved yet:** `/cgi/v1/file_upload` returns HTTP 200 with body respCode 403 to
every non-browser client tried (cookie, cookie+Bearer, token as query param,
with Referer/Origin), so the file never spools and the import then returns
respCode -1. The browser sends some additional session/CSRF binding not yet
captured at the byte level. `Client.UploadCertificate` implements the recipe and
the disable-HTTPS-first safety, ready for when that gate is understood; until
then, install through the UI. LE renews ~every 90 days, so this is a periodic
manual step.

## Getting credentials into a recovery pod safely

`sshpass -e` reads the password from `$SSHPASS`, so it never appears on a
command line or in container logs:

```yaml
command: ["sh","-c"]
args: ["sshpass -e ssh -o PreferredAuthentications=password admin@<switch> '<cmd>'"]
env:
  - name: SSHPASS
    valueFrom:
      secretKeyRef: { name: xs508tm-admin, key: password }
```
