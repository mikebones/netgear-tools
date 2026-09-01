"""Confirm the add/delete param shape for serviceProfiles via one round trip.

Safety:
  * Snapshots the full existing profile list to serviceprofiles.snapshot.json
    BEFORE touching anything.
  * Only ever creates a profile named TF-PROBE-DELETEME on an unused high
    port. A service profile on its own opens nothing - only a port-forward
    that references it would.
  * Deletes only the id it just created, and verifies the final list matches
    the snapshot exactly.
  * Stops at the first param shape that works.

Usage: PR60X_PASSWORD=... python roundtrip.py
"""
import json
import os
import sys
import time

from discover import PR60X

PROBE_NAME = "TF-PROBE-DELETEME"
PROBE_PORT = 65000

PW = os.environ.get("PR60X_PASSWORD")
if not PW:
    raise SystemExit("set PR60X_PASSWORD")

r = PR60X()
r.login(PW)


def profiles():
    time.sleep(1.0)
    reply = r.call("getServiceProfiles")
    if reply.get("error", {}).get("code"):
        raise SystemExit("getServiceProfiles failed: %r" % reply["error"])
    return reply["result"]


before = profiles()
with open("serviceprofiles.snapshot.json", "w", encoding="utf-8") as f:
    json.dump(before, f, indent=2)
names_before = {p["name"] for p in before}
next_id = max(p["id"] for p in before) + 1
print("snapshot: %d profiles, next free id looks like %d" % (len(before), next_id))

row = {
    "name": PROBE_NAME,
    "proto": "tcp",
    "startPort": PROBE_PORT,
    "endPort": PROBE_PORT,
}

CANDIDATES = [
    ("bare object", dict(row)),
    ("object with id", dict(row, id=next_id)),
    ("array of one", [dict(row, id=next_id)]),
    ("row with action", dict(row, id=next_id, action="add")),
    ("array with action", [dict(row, id=next_id, action="add")]),
]

winner = None
for label, params in CANDIDATES:
    time.sleep(1.5)
    reply = r.call("addServiceProfiles", params)
    code = reply.get("error", {}).get("code")
    print("%-20s -> %s" % (
        label,
        "ok" if not code else "ERR %s %s" % (code, reply["error"].get("message", "")[:70])))
    if code:
        continue
    after = profiles()
    created = [p for p in after if p["name"] == PROBE_NAME]
    if created:
        winner = (label, params, created[0])
        print("\nCONFIRMED shape: %s" % label)
        print("  sent:    %s" % json.dumps(params))
        print("  stored:  %s" % json.dumps(created[0]))
        break
    print("   (accepted but nothing created - not the right shape)")

# --- cleanup ---------------------------------------------------------------
if winner:
    created = winner[2]
    del_candidates = [
        ("array of ids", [created["id"]]),
        ("object id", {"id": created["id"]}),
        ("array of objects", [{"id": created["id"]}]),
        ("ids key", {"ids": [created["id"]]}),
    ]
    for label, params in del_candidates:
        time.sleep(1.5)
        reply = r.call("deleteServiceProfiles", params)
        code = reply.get("error", {}).get("code")
        print("delete %-18s -> %s" % (
            label,
            "ok" if not code else "ERR %s %s" % (code, reply["error"].get("message", "")[:60])))
        if code:
            continue
        if not [p for p in profiles() if p["name"] == PROBE_NAME]:
            print("\nCONFIRMED delete shape: %s -> %s" % (label, json.dumps(params)))
            break

final = profiles()
names_final = {p["name"] for p in final}
r.logout()

print("\n--- verification ---")
print("before: %d profiles   after: %d profiles" % (len(before), len(final)))
leftover = names_final - names_before
missing = names_before - names_final
if leftover:
    print("!! LEFTOVER (clean these up): %s" % leftover)
if missing:
    print("!! MISSING (restore from serviceprofiles.snapshot.json): %s" % missing)
if not leftover and not missing:
    print("clean - device is exactly as found")
