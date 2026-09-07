# XS508TM: recovering when the web interface is gone

Written after taking sw2's management interface down with a certificate
upload on 2026-09-07. Everything here was learned during that recovery.

## First: check what actually broke

A dead web UI on this switch is almost always **lighttpd**, not the switch.
The two are worth separating before doing anything drastic:

```
ping <switch>                 # data plane and management IP
nmap -Pn -p 1-1024 <switch>   # what is still listening
kubectl get nodes             # is anything downstream actually affected
```

In the 2026-09-07 incident the switch kept forwarding perfectly throughout —
all cluster nodes Ready, all 48 Longhorn volumes healthy, uninterrupted. Only
ports 80 and 443 were gone. **A dead web UI is not an outage**, and treating
it like one leads to reboots that risk far more than they fix.

## SSH is the way back in — enable it in advance

Port 22 was the only thing still listening, and the admin password works over
it. That single fact is the difference between a config change and a site
visit.

**Enable SSH before you touch certificates**, not after. Once lighttpd is
down there is no API to enable it with.

```
ssh admin@<switch>
(XS508TM)>enable
(XS508TM)#
```

## What the CLI can and cannot do

Useful:

| Command | Does |
| --- | --- |
| `show application` | lists the OpEN apps, including `lighttpdMon` and `RestAgent` |
| `application stop/start <name>` | restarts an app without rebooting |
| `show sysinfo` | uptime — the only reliable way to confirm a reboot happened |
| `dir` | lists flash: images, `certs/`, `lighttpd/`, crash logs |
| `copy <src> <url>` | exports logs/config over tftp/ftp/scp/sftp/http |
| `copy <url> <dest>` | installs code, config, CA roots, client certs, SSH keys |
| `reload` | reboot |
| `terminal length 0` | disable the pager — do this first or `?` output truncates |

**What it cannot do, which is the important half:**

* No `crypto`, `certificate` or `ssl` commands exist anywhere, in any mode.
* `ip http` offers only `accounting` and `authentication`.
* `copy <url> ?` has destinations for `ca-root`, `client-ssl-cert`,
  `root-ca-certs`, `sshkey-*`, configs and images — **but nothing for the web
  server's own certificate**.
* `dir` takes no argument, so flash subdirectories cannot be listed.
* `debug` exposes protocol trace flags only. There is no shell.

So a broken web certificate **cannot be repaired from the CLI**. That is the
finding that matters.

## Things that did not work

Recorded so nobody spends the time again:

* `application stop lighttpdMon` then `start` — reports "Application started",
  ports stay closed. lighttpd dies again immediately on the bad certificate.
* `reload` — confirmed by uptime that it rebooted; ports still closed. The
  certificate lives on flash, not in the config, so it survives.
* Exporting `nvram:crash-log`, `nvram:errorlog`, `nvram:operational-log` over
  TFTP — the transfer starts and creates the file, but all arrive **0 bytes**
  after a reboot.

### The reload prompts need pacing

`reload` asks two questions that read a **single character with no newline**.
Piping `printf 'enable\nreload\nn\ny\n'` desynchronises and the `y` lands as a
command instead of an answer. Pace it:

```sh
( echo enable; sleep 2; echo reload; sleep 3; printf 'n'; sleep 3; printf 'y'; sleep 8 ) \
  | sshpass -e ssh -tt admin@<switch>
```

`n` declines "save unsaved changes", `y` confirms the reset.

## Last resort

`clear config` — a full factory reset. It is the only reset the CLI offers,
it is all-or-nothing, and **it drops the management IP**, so the switch comes
back on a default address. Have console access before running it.

For this network most of the switch's configuration is in Terraform
(`netgear_xs508tm_*`), so rebuilding is realistic — but the IP has to be
recovered first.

## Getting credentials into a recovery pod safely

`sshpass -e` reads the password from `$SSHPASS`, so it never appears in a
command line or in container logs:

```yaml
command: ["sh","-c"]
args: ["sshpass -e ssh -o PreferredAuthentications=password admin@<switch> '<cmd>'"]
env:
  - name: SSHPASS
    valueFrom:
      secretKeyRef: { name: xs508tm-admin, key: password }
```
