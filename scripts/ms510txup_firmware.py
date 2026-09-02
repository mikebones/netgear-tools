"""Upgrade an MS510TXUP over TFTP. The HTTP upload CGI does NOT work.

Both paths transfer the image and both report success. Only TFTP produces an
image the switch will actually boot.

    HTTP  cgi-bin/httpupload.cgi
          The image lands, its metadata parses (show bootvar reports the right
          version, build date and filename), and the boot selection genuinely
          moves. The loader then boots the OLD image anyway and silently clears
          the selection. Reproduced with two different images - including
          1.0.5.23, one release along from what was running - and with a
          multipart encoder verified byte-for-byte against a local server. The
          transfer is fine; the commit never happens. It also answers HTTP 404
          on a successful upload, so its status code tells you nothing.

    TFTP  cgi/set.cgi?cmd=file_tftp_download
          Works. Verified 2026-09-01 taking a live switch
          1.0.5.15 -> 1.0.5.23 -> 1.1.1.9.

Serve the image with scripts/tftp_serve.py (stdlib, read-only) and point the
switch at it - the switch pulls. `txFileName` is capped at 32 characters by the
firmware, which the vendor filenames fit.

WHAT THE UPGRADE RESETS

It does not preserve everything. Going to 1.1.1.9 on the live switch dropped
the remote syslog host entirely and replaced the configured SNTP server with
three vendor defaults (time-a/time-b.netgear.com, 0.openwrt.pool.ntp.org). DNS
and the clock source survived. Re-run Terraform afterwards rather than assuming
the config came through - that drift is exactly what the state is for, and it
caught both.

Usage:

    # terminal 1 - serve the directory holding the .bix (port 69 needs root)
    python tftp_serve.py /path/to/firmware 69

    # terminal 2
    MS510_PASSWORD=... python ms510txup_firmware.py \\
        --server 192.168.1.140 --file MS510TXM_TXUP_V1.1.1.9.bix --activate

--activate selects the written slot for the next boot. It does NOT reboot:
rebooting interrupts forwarding for everything attached, and on this switch
that includes PoE-powered cluster nodes.
"""
import argparse
import json
import os
import time

from ms510txup_login import MS510

FILETYPE_FIRMWARE = "0"
MAX_FILENAME = 32


def dual_status(sw):
    return sw.get("file_dualStatus").get("data", {}).get("status", [{}])[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True,
                    help="TFTP server address, reachable FROM THE SWITCH")
    ap.add_argument("--file", required=True, help="image filename on that server")
    ap.add_argument("--path", default="./", help="path on the TFTP server")
    ap.add_argument("--activate", action="store_true",
                    help="select the written slot for next boot (does not reboot)")
    args = ap.parse_args()

    if len(args.file) > MAX_FILENAME:
        raise SystemExit("txFileName is capped at %d characters by the firmware" % MAX_FILENAME)

    sw = MS510()
    sw.login(os.environ["MS510_PASSWORD"])
    try:
        sw.refresh_xsrf()
        before = dual_status(sw)
        print("  before: img1=%s img2=%s active=%s next=%s" % (
            before.get("img1Ver"), before.get("img2Ver"),
            before.get("curAct"), before.get("nextAct")))

        # Always write the slot that is not running, so a bad image costs a
        # reboot rather than a switch.
        target_slot = "0" if before.get("curAct") == "image2" else "1"
        target_name = "image1" if target_slot == "0" else "image2"
        old_version = before.get("img1Ver") if target_slot == "0" else before.get("img2Ver")
        print("  writing %s (the inactive slot)" % target_name)

        res = sw.set("file_tftp_download", {
            "fileType": FILETYPE_FIRMWARE,
            "imgName": target_slot,
            "addrType": "0",  # IPv4
            "srvAddr": args.server,
            "txFilePath": args.path,
            "txFileName": args.file,
            "startTx": "on",
        })
        print("  file_tftp_download ->", json.dumps(res)[:140])

        # Poll the switch, not the transfer: it keeps reporting "uploading" for
        # a while after the last byte lands, while it writes flash.
        for i in range(40):
            time.sleep(20)
            st = sw.get("file_tftp_downloadStatus").get("data", {})
            now = dual_status(sw)
            seen = now.get("img1Ver") if target_slot == "0" else now.get("img2Ver")
            print("   t+%4ds status=%-12s %s=%s" % ((i + 1) * 20, st.get("status"), target_name, seen),
                  flush=True)
            if st.get("status") not in ("uploading", "downloading", "inprogress"):
                break
        else:
            raise SystemExit("the transfer never finished")

        after = dual_status(sw)
        written = after.get("img1Ver") if target_slot == "0" else after.get("img2Ver")
        if written == old_version:
            raise SystemExit("%s still holds %s - the image did not land" % (target_name, old_version))
        print("  %s now holds %s" % (target_name, written))

        if args.activate:
            # file_dualStatus is read-only - the write lives on file_dualConf.
            print("  activating %s ->" % target_name,
                  json.dumps(sw.set("file_dualConf",
                                    {"imgName": target_slot, "imgActive": "on"}))[:120])
            final = dual_status(sw)
            print("  next boot: %s" % final.get("nextAct"))
            if final.get("nextAct") != target_name:
                raise SystemExit("next-active did not move to %s - not safe to reboot" % target_name)
            print("  reboot when ready, then re-run terraform: the upgrade resets some config")
    finally:
        sw.logout()


if __name__ == "__main__":
    main()
