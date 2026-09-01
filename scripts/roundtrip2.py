"""Confirm the edit shape, and the port-forwarding add/edit/delete shapes.

Safety:
  * Snapshots BOTH tables before touching anything.
  * The probe port-forwarding rule is created with enabled=0, so no port is
    ever actually opened to the internet, and it points at an unused address.
  * Everything created is deleted again, and both tables are diffed against
    the snapshots at the end.

Usage: PR60X_PASSWORD=... python roundtrip2.py
"""
import json
import os
import sys
import time

from discover import PR60X

PROBE_SVC = "TF-PROBE-DELETEME"
PROBE_PORT = 65000
PROBE_DEST = "192.168.1.254"  # unused; rule stays disabled regardless

PW = os.environ.get("PR60X_PASSWORD")
if not PW:
    raise SystemExit("set PR60X_PASSWORD")

r = PR60X()
r.login(PW)


def call(method, params=None, quiet=False):
    time.sleep(1.2)
    reply = r.call(method, params)
    code = reply.get("error", {}).get("code")
    if code and not quiet:
        sys.stderr.write("    %s -> ERR %s %s\n"
                         % (method, code, reply["error"].get("message", "")[:70]))
    return reply, code


def profiles():
    reply, code = call("getServiceProfiles", quiet=True)
    if code:
        raise SystemExit("getServiceProfiles failed: %r" % reply)
    return reply["result"]


def rules():
    reply, code = call("getPortForwardingRules", quiet=True)
    if code:
        raise SystemExit("getPortForwardingRules failed: %r" % reply)
    return reply["result"]


svc_before = profiles()
pf_before = rules()
json.dump({"serviceProfiles": svc_before, "portForwardingRules": pf_before},
          open("roundtrip2.snapshot.json", "w", encoding="utf-8"), indent=2)
print("snapshot: %d service profiles, %d forwarding rules"
      % (len(svc_before), len(pf_before)))

svc_id = max(p["id"] for p in svc_before) + 1
created_svc = created_pf = None
results = {}

try:
    # --- 1. create the probe service profile (shape already confirmed) ------
    row = {"id": svc_id, "name": PROBE_SVC, "proto": "tcp",
           "startPort": PROBE_PORT, "endPort": PROBE_PORT, "action": "add"}
    _, code = call("addServiceProfiles", [row])
    if code:
        raise SystemExit("could not create probe profile - aborting")
    created_svc = svc_id
    print("created probe service profile id=%d" % svc_id)

    # --- 2. confirm the EDIT shape -----------------------------------------
    print("\n-- editServiceProfiles --")
    edit_candidates = [
        ("array + action edit", [dict(row, endPort=PROBE_PORT + 1, action="edit")]),
        ("array no action", [{"id": svc_id, "name": PROBE_SVC, "proto": "tcp",
                              "startPort": PROBE_PORT, "endPort": PROBE_PORT + 1}]),
        ("bare object", {"id": svc_id, "name": PROBE_SVC, "proto": "tcp",
                         "startPort": PROBE_PORT, "endPort": PROBE_PORT + 1}),
    ]
    for label, params in edit_candidates:
        _, code = call("editServiceProfiles", params)
        if code:
            continue
        got = [p for p in profiles() if p["id"] == svc_id]
        if got and got[0].get("endPort") == PROBE_PORT + 1:
            results["editServiceProfiles"] = (label, params)
            print("  CONFIRMED edit shape: %s" % label)
            break
        print("  %s accepted but value unchanged" % label)
    else:
        print("  !! no edit shape confirmed")

    # --- 3. confirm the port-forwarding ADD shape --------------------------
    # enabled=0 throughout: this must never actually open a port.
    print("\n-- addPortForwardingRules (probe rule stays DISABLED) --")
    pf_id = (max((x["id"] for x in pf_before), default=-1)) + 1
    pf_row = {
        "id": pf_id,
        "enabled": 0,
        "externalService": PROBE_SVC,
        "internalService": PROBE_SVC,
        "destIpAddress": PROBE_DEST,
        "srcIpAddress": "Any",
        "wanInputInterface": "wan",
        "wanIpAddress": "",
    }
    pf_candidates = [
        ("array + action add", [dict(pf_row, action="add")]),
        ("array no action", [dict(pf_row)]),
        ("bare object", dict(pf_row)),
    ]
    for label, params in pf_candidates:
        _, code = call("addPortForwardingRules", params)
        if code:
            continue
        got = [x for x in rules() if x["externalService"] == PROBE_SVC]
        if got:
            created_pf = got[0]["id"]
            results["addPortForwardingRules"] = (label, params)
            print("  CONFIRMED add shape: %s" % label)
            print("  stored: %s" % json.dumps(got[0]))
            assert got[0]["enabled"] == 0, "probe rule came back ENABLED - deleting"
            break
        print("  %s accepted but nothing created" % label)
    else:
        print("  !! no port-forward add shape confirmed")

finally:
    # --- cleanup -----------------------------------------------------------
    print("\n-- cleanup --")
    if created_pf is not None:
        _, code = call("deletePortForwardingRules", [created_pf])
        print("  delete rule %d: %s" % (created_pf, "ok" if not code else "FAILED"))
        if not code:
            results["deletePortForwardingRules"] = ("array of ids", [created_pf])
    if created_svc is not None:
        _, code = call("deleteServiceProfiles", [created_svc])
        print("  delete profile %d: %s" % (created_svc, "ok" if not code else "FAILED"))

    svc_after = profiles()
    pf_after = rules()
    r.logout()

    print("\n--- verification ---")
    print("service profiles: %d -> %d" % (len(svc_before), len(svc_after)))
    print("forwarding rules: %d -> %d" % (len(pf_before), len(pf_after)))
    leftover = ([p["name"] for p in svc_after if p["name"] == PROBE_SVC] +
                [x["externalService"] for x in pf_after if x["externalService"] == PROBE_SVC])
    missing = ({p["name"] for p in svc_before} - {p["name"] for p in svc_after}) | \
              ({x["id"] for x in pf_before} - {x["id"] for x in pf_after})
    if leftover:
        print("!! LEFTOVER, clean up manually: %s" % leftover)
    if missing:
        print("!! MISSING, restore from roundtrip2.snapshot.json: %s" % missing)
    if not leftover and not missing:
        print("clean - device is exactly as found")

    print("\n--- confirmed shapes ---")
    for k, (label, params) in results.items():
        print("%-28s %-20s %s" % (k, label, json.dumps(params)[:140]))
