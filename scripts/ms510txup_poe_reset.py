"""Power-cycle PoE on selected MS510TXUP ports.

Why this exists: the switch defaults to UNINTERRUPTIBLE PoE (`unintr: 1` in
poe_conf), which keeps powered devices up across a management reboot. That is
usually what you want - rebooting the switch does not reboot the phones and
cameras hanging off it - but it means a halted device stays halted, because it
never sees the power cycle it needs to boot again.

Confirmed on 2026-09-01: rebooting the switch left all four Pis halted and
still drawing ~2.4W, reported as "Delivering" with no fault - and this reset is
what actually brought them back.

That is exactly the trap here: `shutdown -h now` on the Raspberry Pis halts
them, the switch reboot leaves PoE up, and they sit drawing ~2.4W each,
reported as "Delivering" with no fault and no link. Everything looks healthy
and nothing is running. This resets the port so power actually drops and comes
back.

Usage:

    MS510_PASSWORD=... python ms510txup_poe_reset.py 1 2 3 4

Ports are given as they appear in the UI (1-based); the CGI wants 0-based row
indices and the conversion is done here. Ports are reset one at a time with a
gap, to avoid every device drawing inrush current simultaneously.
"""
import json
import os
import sys
import time

from ms510txup_login import MS510


def reset_ports(sw, ui_ports, gap=4.0):
    """Reset PoE on the given 1-based UI port numbers."""
    sw.refresh_xsrf()
    for port in ui_ports:
        # The reset form posts the selected rows as repeated selEntry values,
        # 0-based. urlencode() cannot express a repeated key, so build it here.
        body = "_ds=1&selEntry=%d&xsrf=%s&_de=1" % (port - 1, sw.xsrf)
        res = sw._request("cgi/set.cgi?cmd=poe_portReset", body.encode())
        if isinstance(res, dict) and res.get("xsrf"):
            sw.xsrf = res["xsrf"]
        print("  reset PoE on port %d -> %s" % (port, json.dumps(res)[:120]))
        time.sleep(gap)


def main():
    ports = [int(a) for a in sys.argv[1:]]
    if not ports:
        print(__doc__)
        raise SystemExit("give at least one port number")

    sw = MS510()
    sw.login(os.environ["MS510_PASSWORD"])
    try:
        before = sw.get("poe_port").get("data", {}).get("ports", [])
        for p in ports:
            if 1 <= p <= len(before):
                e = before[p - 1]
                print("  port %d before: %s %smW" % (p, e.get("status", ""), e.get("power")))
        reset_ports(sw, ports)
    finally:
        sw.logout()


if __name__ == "__main__":
    main()
