"""Upgrade a WAX630E access point by uploading a firmware .tar to it.

The AP has no online update check - it only accepts a file. The UI's three
"firmwareLocal" calls are NOT a three-step upload, which is the easy thing to
assume from their names:

    firmwareLocal1  POST /file/firmwareupgrade   check: 1   multipart, field "file"
                    The whole upload. On an upgrade this is the only call
                    needed: status 0 means accepted, and the AP applies it and
                    reboots on its own (~3 minutes).

    firmwareLocal2  POST /local_firmware         check: 2   no body
                    CONFIRM A DOWNGRADE. Only reached when firmwareLocal1
                    answers status 9, and confirming it FACTORY RESETS the AP -
                    the UI spells out that configuration is wiped and the SSID
                    reverts to a default with a published password.

    firmwareLocal3  POST /local_firmware         check: 3   no body
                    Cancel that downgrade.

This script therefore refuses to do anything except a clean upgrade. Status 9
aborts rather than confirming, because a factory reset is not something to
trigger from a firmware helper.

Status codes from firmwareLocal1:

    0    accepted, the AP is applying it and will reboot
    3    not a valid firmware file
    8    not enough free RAM - reboot the AP and retry
    9    downgrade (would factory reset)
    100  not authenticated

The file must be a .tar - the AP checks the extension, and the vendor zip
contains exactly one.

A CAUTION ABOUT THE MANAGEMENT PATH: the AP terminates wireless. Running this
from a machine connected over that same AP drops the connection the upgrade is
being driven from. Use a wired host.

Usage:

    WAX630_PASSWORD=... python wax630e_firmware.py \\
        --file /path/to/WAX630E-638E_V10.8.10.10_firmware.tar
"""
import argparse
import json
import os
import urllib.request
import uuid

from wax630e_client import WAX630E

STATUS = {
    "0": "accepted - the AP is applying it and will reboot",
    "3": "rejected: not a valid firmware file",
    "8": "rejected: not enough free RAM, reboot the AP and retry",
    "9": "this is a DOWNGRADE, which factory resets the AP",
    "100": "not authenticated",
}


def main():
    ap_args = argparse.ArgumentParser()
    ap_args.add_argument("--file", required=True, help="firmware .tar")
    ap_args.add_argument("--host", default=os.environ.get("WAX630_HOST", "https://192.168.1.136"))
    args = ap_args.parse_args()

    if not args.file.endswith(".tar"):
        raise SystemExit("the AP only accepts a .tar - the vendor zip contains one")
    blob = open(args.file, "rb").read()
    print("  image: %s (%d bytes)" % (os.path.basename(args.file), len(blob)))

    ap = WAX630E(args.host)
    ap.login(os.environ.get("WAX630_USERNAME", "admin"), os.environ["WAX630_PASSWORD"])
    try:
        before = ap.get("dashboard")["system"]["monitor"].get("sysVersion")
        print("  running: %s" % before)

        boundary = "----wax" + uuid.uuid4().hex
        sep = ("--" + boundary).encode()
        body = b"\r\n".join([
            sep,
            ('Content-Disposition: form-data; name="file"; filename="%s"'
             % os.path.basename(args.file)).encode(),
            b"Content-Type: application/octet-stream", b"", blob,
        ]) + b"\r\n" + sep + b"--\r\n"

        req = urllib.request.Request(
            ap.host + "/file/firmwareupgrade", data=body, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=" + boundary,
                     "Content-Length": str(len(body)),
                     "check": "1", "security": ap.token})
        print("  uploading, this takes a few minutes ...", flush=True)
        with ap.opener.open(req, timeout=900) as r:
            raw = r.read().decode("utf-8", "replace")

        status = str(json.loads(raw).get("status")) if raw.strip().startswith("{") else "?"
        print("  reply: %s  (%s)" % (raw[:120], STATUS.get(status, "unrecognised status")))

        if status != "0":
            # Deliberately does not call firmwareLocal2 on status 9.
            raise SystemExit("not applied")
        print("  the AP reboots on its own; allow ~3 minutes, then re-run terraform")
        print("  NOTE: the AP caps concurrent sessions - do not poll it hard while")
        print("  it comes back, or logins start failing with status 401")
    finally:
        try:
            ap.logout()
        except Exception:
            pass


if __name__ == "__main__":
    main()
