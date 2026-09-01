"""Gently collect the schemas still missing after discovery.py.

The device's backend config daemon ("process_configd_request") degrades under
rapid RPC load - the first pass wedged it after ~49 back-to-back calls. This
script paces deliberately: one call every PACE seconds, a fresh session every
BATCH calls, and it aborts rather than hammering if configd starts failing.

Usage: PR60X_PASSWORD=... python collect.py
"""
import json
import os
import sys
import time

from discover import PR60X

PACE = 2.0     # seconds between calls
BATCH = 10     # calls per session
COOLDOWN = 3.0  # seconds between sessions

WANTED = [
    "getServiceProfiles",         # port-forward rules reference these by name
    "getStaticLeaseProfiles",
    "getStaticRoutes",
    "getWireGuardServerProfile",
    "getWireGuardPeerProfiles",
    "getVlanProfiles",
    "getVlanPorts",
    "getWanProfiles",
    "getWanType",
    "getUpnpSettings",
    "getUpnpPortMapTable",
    "getTrafficRules",
    "getSnmpSettings",
    "getVpnUsers",
    "getWiredPortLinkDetails",
]

PW = os.environ.get("PR60X_PASSWORD")
if not PW:
    raise SystemExit("set PR60X_PASSWORD")

data = json.load(open("discovery.json", encoding="utf-8"))

r = PR60X()
r.login(PW)
sys.stderr.write("session up\n")

n = 0
consecutive_500 = 0
try:
    for m in WANTED:
        if n and n % BATCH == 0:
            r.logout()
            time.sleep(COOLDOWN)
            r.login(PW)
            sys.stderr.write("  -- new session --\n")

        reply = r.call(m)
        n += 1
        code = reply.get("error", {}).get("code")

        if code:
            data[m] = {"error": reply["error"]}
            sys.stderr.write("%-32s ERR %s %s\n"
                             % (m, code, reply["error"].get("message", "")[:60]))
            consecutive_500 = consecutive_500 + 1 if code == 500 else 0
            if consecutive_500 >= 3:
                sys.stderr.write("\nconfigd degrading - stopping early.\n")
                break
        else:
            data[m] = {"result": reply.get("result")}
            consecutive_500 = 0
            sys.stderr.write("%-32s ok\n" % m)

        time.sleep(PACE)
finally:
    r.logout()

with open("discovery.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)

remaining = sorted(k for k, v in data.items()
                   if not k.startswith("_") and "error" in v)
sys.stderr.write("\nstill missing: %s\n" % (remaining or "none"))
