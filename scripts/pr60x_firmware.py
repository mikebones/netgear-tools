"""Check for and apply a PR60X firmware update using the router's own updater.

The PR60X is the only one of these four devices with an online update path -
it fetches the image from NETGEAR itself, so there is nothing to stage. It is
the "check for updates" button in the UI, and it is fully exposed:

    checkFirmwareUpgrade         ask NETGEAR whether there is one
    getFirmwareUpgrade           what is available
    startFirmwareDownload        fetch it
    getFirmwareDownloadProgress  poll - reaches state "success" at 99%
    updateFirmware               APPLY it and reboot

The one that catches you out is the last pair. startFirmwareDownload only
downloads: progress parks at state "success", downloadPercent 99, and stays
there indefinitely. Nothing happens until updateFirmware is called separately
with {"mode": "online", "factoryReset": 0}.

factoryReset 0 keeps the configuration, and it is what the UI's own online
path sends. Verified on 2026-09-01 taking a live router 2.7.0.111 -> 3.0.0.105
with zero config drift: port forwards, service profiles, syslog, SQM, UPnP and
the DHCP DNS setting all survived a major version jump, confirmed by a clean
terraform plan across every managed resource afterwards.

The router reboots and is back in about 90 seconds. Cluster nodes do not talk
through it, so the outage is internet access only.

Usage:

    PR60X_PASSWORD=... python pr60x_firmware.py            # check only
    PR60X_PASSWORD=... python pr60x_firmware.py --apply    # download and apply
"""
import argparse
import http.cookiejar
import json
import os
import ssl
import time
import urllib.request

HOST = os.environ.get("PR60X_ENDPOINT", "https://192.168.1.1")

_ctx = ssl._create_unverified_context()
_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ctx),
    urllib.request.HTTPCookieProcessor(_jar))


def rpc(method, params=None, token=None, timeout=60):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Security"] = token
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params or {}, "id": 1}).encode()
    req = urllib.request.Request(HOST + "/socketCommunication", data=body,
                                 headers=headers, method="POST")
    with _opener.open(req, timeout=timeout) as r:
        out = json.loads(r.read().decode())
    if "error" in out:
        raise SystemExit("%s failed: %s" % (method, json.dumps(out["error"])))
    return out.get("result")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="download AND apply; without this it only reports")
    args = ap.parse_args()

    # GET / first: it sets the lhttpdsid cookie, and without it login fails
    # with -32602, which looks exactly like a wrong password.
    _opener.open(urllib.request.Request(HOST + "/"), timeout=20).close()
    token = rpc("login", {"username": os.environ.get("PR60X_USERNAME", "admin"),
                          "password": os.environ["PR60X_PASSWORD"]})["token"]
    try:
        running = rpc("getDeviceInfo", {}, token).get("firmwareVersion")
        rpc("checkFirmwareUpgrade", {}, token)
        avail = rpc("getFirmwareUpgrade", {}, token)
        print("  running   : %s" % running)
        print("  available : %s (upgrade available: %s)"
              % (avail.get("firmwareVersion"), avail.get("isUpgradeAvailable")))

        if not args.apply:
            print("  check only - pass --apply to download and install")
            return
        if not avail.get("isUpgradeAvailable"):
            print("  nothing to do")
            return

        print("  downloading ...", flush=True)
        rpc("startFirmwareDownload", {}, token)
        for _ in range(60):
            time.sleep(15)
            p = rpc("getFirmwareDownloadProgress", {}, token)
            print("   state=%-12s %s%%" % (p.get("state"), p.get("downloadPercent")), flush=True)
            # "success" is as far as it goes - it does NOT self-apply.
            if p.get("state") == "success":
                break
        else:
            raise SystemExit("the download never reached success")

        print("  applying (factoryReset 0 keeps the configuration) ...", flush=True)
        rpc("updateFirmware", {"mode": "online", "factoryReset": 0}, token, timeout=130)
        print("  applied; the router reboots and returns in about 90 seconds")
        print("  re-run terraform afterwards to confirm nothing drifted")
    finally:
        try:
            rpc("logout", {}, token)
        except Exception:
            pass


if __name__ == "__main__":
    main()
