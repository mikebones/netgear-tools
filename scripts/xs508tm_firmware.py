"""Upgrade an XS-series switch (XS508TM / XS516TM / XS724TM) over its SSH CLI.

Unlike the MS510TXUP - whose HTTP upload CGI accepts an image and then never
makes it bootable - this family exposes the vendor's own supported upgrade path
on the CLI, and it works:

    copy http://<host>:<port>/<file>.stk image<inactive>
    boot system image<inactive>
    reload

Proven on 2026-09-01: 7.8.11.16 -> 7.8.11.21 on a live XS508TM, ~40MB over
HTTP, config preserved across the reboot.

WHY THIS IS SAFE ENOUGH TO AUTOMATE

The switch is dual-image and this script always writes the INACTIVE slot,
refusing to touch the running one. If the new image does not come up, the old
one is still there. It also saves the running config first, because the CLI
otherwise offers to do it mid-reload behind an interactive prompt, and an
unanswered prompt in the middle of a teardown is a bad place to be.

To correct something stated here earlier: the REST API DOES persist to
startup-config. Verified by writing a syslog severity over the API and diffing
`show running-config` against `show startup-config` - both changed together.
The "system has unsaved changes" seen during this work came from CLI actions
(`application stop/start`, image activation), not from Terraform. Saving here
is cheap insurance for whatever else touched the box, not a workaround for the
provider.

WHY SSH RATHER THAN THE REST API

The management plane is what tends to be broken when you most need to upgrade.
This switch's RestAgent had been returning 502 for days - through an
application restart AND a full reboot - while SSH stayed perfectly healthy.
The firmware upgrade is what finally cleared it. An upgrade path that depends
on the API cannot fix the API.

PROMPTS

The CLI asks single-character y/n questions with no newline, and it keeps
emitting output while you type. Every send here waits for the device to go
quiet first (see `drain`); sending a command into a still-scrolling buffer gets
the first character eaten, which is how "write memory" once became "rite
memory".

Usage:

    XS508TM_PASSWORD=... python xs508tm_firmware.py \\
        --host 192.168.1.223 --url http://192.168.1.140:8800/S3600-v7.8.11.21.stk

    ... --activate      also set next-boot and reload
"""
import argparse
import os
import re
import sys
import time

import paramiko

TRANSFER_TIMEOUT = 900


class SwitchCLI:
    def __init__(self, host, password, username="admin"):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, username=username, password=password,
                            look_for_keys=False, allow_agent=False, timeout=30)
        self.sh = self.client.invoke_shell(width=220, height=1200)
        time.sleep(3)
        self.drain()
        self.send("enable")
        self.send("terminal length 0")

    def drain(self, idle=3.0, cap=TRANSFER_TIMEOUT):
        """Read until the switch has been quiet for `idle` seconds."""
        buf = b""
        last = start = time.time()
        while time.time() - last < idle and time.time() - start < cap:
            if self.sh.recv_ready():
                buf += self.sh.recv(65535)
                last = time.time()
            time.sleep(0.2)
        return buf.decode("utf-8", "replace")

    def send(self, cmd, idle=3.0, cap=TRANSFER_TIMEOUT):
        self.sh.send(cmd + "\n")
        return self.drain(idle, cap)

    def answer(self, char="y", idle=3.0, cap=TRANSFER_TIMEOUT):
        """Reply to a single-character prompt - no newline, or it is echoed."""
        self.sh.send(char)
        return self.drain(idle, cap)

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass


def parse_bootvar(text):
    """Pull (image1, image2, current_active, next_active) out of show bootvar."""
    for line in text.split("\n"):
        m = re.match(r"\s*\d+\s+(\S+)\s+(\S+)\s+(image\d)\s+(image\d)\s*$", line)
        if m:
            return m.groups()
    return None


def save_config(cli):
    out = cli.send("write memory")
    if "y/n" in out.lower():
        out = cli.answer("y", idle=8.0)
    if "Configuration Saved" not in out and "created successfully" not in out:
        print("  WARNING: could not confirm the config was saved:\n%s" % out[-300:])
    else:
        print("  running-config saved to startup-config")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--url", required=True,
                    help="http:// URL of the .stk image, reachable FROM THE SWITCH")
    ap.add_argument("--activate", action="store_true",
                    help="set next-boot to the newly written slot and reload")
    args = ap.parse_args()

    cli = SwitchCLI(args.host, os.environ["XS508TM_PASSWORD"])
    try:
        boot = parse_bootvar(cli.send("show bootvar", idle=4.0))
        if not boot:
            raise SystemExit("could not parse `show bootvar`")
        img1, img2, active, nxt = boot
        print("  before: image1=%s image2=%s active=%s next=%s" % (img1, img2, active, nxt))

        # Always write the slot that is NOT running.
        target = "image1" if active == "image2" else "image2"
        print("  writing %s (the inactive slot)" % target)

        # Save first so `reload` does not stop on its save prompt mid-teardown.
        # (The REST API persists on its own - see the module docstring.)
        save_config(cli)

        out = cli.send("copy %s %s" % (args.url, target), idle=6.0)
        if "y/n" not in out.lower():
            raise SystemExit("copy did not prompt to start:\n%s" % out[-400:])
        print("  transferring (management access is blocked while this runs) ...")
        cli.answer("y", idle=25.0, cap=TRANSFER_TIMEOUT)

        # The transfer continues after the session goes quiet, so poll bootvar
        # rather than trusting the copy output.
        for _ in range(30):
            time.sleep(20)
            try:
                boot = parse_bootvar(cli.send("show bootvar", idle=4.0))
            except Exception:
                boot = None
            if boot:
                new = boot[0] if target == "image1" else boot[1]
                old = img1 if target == "image1" else img2
                print("   %s now holds %s" % (target, new))
                if new != old:
                    break
        else:
            raise SystemExit("the image never appeared in %s" % target)

        if args.activate:
            print("  activating %s" % target)
            print(cli.send("boot system %s" % target, idle=5.0)[-200:].strip())
            boot = parse_bootvar(cli.send("show bootvar", idle=4.0))
            print("  bootvar now: %s" % (boot,))
            if boot and boot[3] != target:
                raise SystemExit("next-active is %s, not %s - refusing to reload" % (boot[3], target))

            out = cli.send("reload", idle=4.0)
            # Two prompts: save changes, then confirm the reset.
            for _ in range(3):
                if "y/n" not in out.lower():
                    break
                out = cli.answer("y", idle=4.0)
            print("  reload issued")
    finally:
        cli.close()


if __name__ == "__main__":
    main()
