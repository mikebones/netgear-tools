"""Set a VLAN's DHCP DNS servers (DHCP option 6) on the PR60X.

Why this exists: a router handing out both a local resolver and a public one
gives every client two nameservers and no rule for choosing between them, so
lookups for private zones fail roughly half the time. Removing the public
entry fixes that at source.

This edits a live VLAN profile, so it is deliberately paranoid:

  * Snapshots every VLAN profile to vlan.snapshot.json before touching one.
  * Sends the profile back BYTE-FOR-BYTE as read, with only dhcpDnsAddr
    changed - it never reconstructs the object from a partial struct, so it
    cannot silently drop ipAddress, the DHCP range, or the port membership.
  * Deep-diffs the result and fails loudly if anything except dhcpDnsAddr
    moved, printing the restore command.

Changing option 6 cannot partition the network: it only affects what future
DHCP leases advertise. Existing clients keep their current resolvers until
they renew.

Usage:
    PR60X_PASSWORD=... python set_dhcp_dns.py --vlan 1 --show
    PR60X_PASSWORD=... python set_dhcp_dns.py --vlan 1 --dns 192.168.1.64
    PR60X_PASSWORD=... python set_dhcp_dns.py --restore vlan.snapshot.json
"""
import argparse
import copy
import json
import os
import sys

from discover import PR60X

SNAPSHOT = "vlan.snapshot.json"


def get_profiles(r):
    reply = r.call("getVlanProfiles")
    if reply.get("error", {}).get("code"):
        raise SystemExit("getVlanProfiles failed: %r" % reply["error"])
    # getVlanProfiles double-wraps: result.result
    return reply["result"]["result"]


def diff(a, b, path=""):
    """Yield (path, old, new) for every leaf that differs."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            yield from diff(a.get(k), b.get(k), "%s.%s" % (path, k))
    elif isinstance(a, list) and isinstance(b, list):
        if a != b:
            yield (path, a, b)
    elif a != b:
        yield (path, a, b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vlan", type=int, default=1)
    ap.add_argument("--dns", nargs="*", help="Ordered DNS servers for DHCP option 6.")
    ap.add_argument("--show", action="store_true", help="Print current settings and exit.")
    ap.add_argument("--restore", metavar="FILE", help="Restore VLAN profiles from a snapshot.")
    args = ap.parse_args()

    pw = os.environ.get("PR60X_PASSWORD")
    if not pw:
        raise SystemExit("set PR60X_PASSWORD")

    r = PR60X()
    r.login(pw)
    try:
        before = get_profiles(r)

        if args.show:
            for p in before:
                s = p["ipv4Settings"]
                print("VLAN %s (%s)" % (p["vlanId"], p["name"]))
                print("  dhcp server : %s" % ("enabled" if s["dhcpServerEnabled"] else "disabled"))
                print("  range       : %s - %s" % (s["dhcpStartIpv4Address"], s["dhcpEndIpv4Address"]))
                print("  option 6    : %s (type %s)" % (s["dhcpDnsAddr"], s["dhcpDnsType"]))
            return

        if args.restore:
            saved = json.load(open(args.restore, encoding="utf-8"))
            for p in saved:
                row = copy.deepcopy(p)
                row["action"] = "edit"
                reply = r.call("editVlanProfiles", [row])
                code = reply.get("error", {}).get("code")
                print("restore VLAN %s: %s" % (p["vlanId"], "ok" if not code else reply["error"]))
            return

        if not args.dns:
            raise SystemExit("give --dns, --show or --restore")

        target = next((p for p in before if p["vlanId"] == args.vlan), None)
        if target is None:
            raise SystemExit("no VLAN with id %d" % args.vlan)

        json.dump(before, open(SNAPSHOT, "w", encoding="utf-8"), indent=2)
        print("snapshot -> %s" % SNAPSHOT)

        current = target["ipv4Settings"]["dhcpDnsAddr"]
        if current == args.dns:
            print("already %s - nothing to do" % current)
            return

        print("VLAN %d option 6: %s -> %s" % (args.vlan, current, args.dns))

        # Send the profile back exactly as read, with one field changed.
        row = copy.deepcopy(target)
        row["ipv4Settings"]["dhcpDnsAddr"] = list(args.dns)
        row["action"] = "edit"

        reply = r.call("editVlanProfiles", [row])
        code = reply.get("error", {}).get("code")
        if code:
            raise SystemExit("editVlanProfiles failed: %r  (device unchanged)" % reply["error"])

        after = get_profiles(r)
        new_target = next((p for p in after if p["vlanId"] == args.vlan), None)
        if new_target is None:
            raise SystemExit("VLAN %d vanished! restore: python %s --restore %s"
                             % (args.vlan, sys.argv[0], SNAPSHOT))

        changes = list(diff(target, new_target))
        expected = ".ipv4Settings.dhcpDnsAddr"
        unexpected = [c for c in changes if c[0] != expected]

        print("\nchanged fields:")
        for path, old, new in changes:
            print("  %-34s %s -> %s" % (path, old, new))
        if not changes:
            print("  (none - device did not apply the edit)")

        if unexpected:
            print("\n!! UNEXPECTED CHANGES - restore with:")
            print("   PR60X_PASSWORD=... python %s --restore %s" % (sys.argv[0], SNAPSHOT))
            raise SystemExit(1)

        if new_target["ipv4Settings"]["dhcpDnsAddr"] == list(args.dns):
            print("\nok - only option 6 changed, and it holds the requested value")
        else:
            print("\n!! option 6 did not take the requested value")
            raise SystemExit(1)
    finally:
        r.logout()


if __name__ == "__main__":
    main()
