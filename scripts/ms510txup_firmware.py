"""Upload a firmware image to an MS510TXUP over its HTTP upload CGI.

The switch is DUAL-IMAGE, which is what makes this safe to automate: write the
new firmware to the inactive slot, leave the running one untouched, and only
then point the next boot at it. If the new image is bad, the switch still has a
known-good one to fall back to.

The upload is a plain multipart POST, but to a different endpoint from the rest
of the API and with its own field order:

    POST /cgi-bin/httpupload.cgi
    X-CSRF-XSID: base64(RSA_PKCS1v15(tabid))     <- same gate as everything else
    multipart/form-data:
        fileType = 0        firmware
        xsrf     = <token>  from home_home
        imgName  = 0|1      image1 | image2
        fileName = <the .bix file>

Note the path carries no query string, so it is NOT bj4-signed - sign() leaves
it alone. The RSA CSRF header still applies.

Usage:

    MS510_PASSWORD=... python ms510txup_firmware.py <file.bix> --image 2
    MS510_PASSWORD=... python ms510txup_firmware.py <file.bix> --image 2 --activate

--activate sets the next boot to the slot just written. It does NOT reboot;
rebooting is a separate, deliberate act because it interrupts forwarding for
everything attached to the switch.

WHAT THIS SCRIPT DOES NOT DO, 2026-09-01: it does not actually complete an
upgrade. The transfer works - the switch stores the image, reports the right
version and build date in `show bootvar`, and file_http_downloadStatus reaches
"success" - and the boot selection really does move. The switch then boots the
old image and clears the selection, silently.

Ruled out: the version jump (1.0.5.23, same series, fails the same way as
1.1.1.9) and a corrupt payload (the multipart body round-trips a 12.3MB image
byte-for-byte against a local server). What remains is that the CGI never
commits the image as bootable, consistent with it answering HTTP 404 on an
upload it otherwise accepts.

USE THE WEB UI TO UPGRADE FIRMWARE. This script is kept because the upload
mechanics are correct and documented, and because knowing exactly how far it
gets is what rules the easy explanations out.

The upload also returns HTTP 404 on success, so never trust the status code -
check file_dualStatus.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

from ms510txup_login import MS510

FILETYPE_FIRMWARE = "0"


def upload(sw, path, image_slot):
    """POST the image into the given slot (1 or 2). Returns the reply dict."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] != b"NGP ":
        raise SystemExit("%s does not start with the NETGEAR 'NGP ' magic - wrong file?" % path)

    sw.refresh_xsrf()
    boundary = "----ms510" + uuid.uuid4().hex
    sep = ("--" + boundary).encode()

    parts = []
    for name, value in (("fileType", FILETYPE_FIRMWARE),
                        ("xsrf", sw.xsrf),
                        ("imgName", str(image_slot - 1))):   # image1 = 0, image2 = 1
        parts.append(sep)
        parts.append(('Content-Disposition: form-data; name="%s"' % name).encode())
        parts.append(b"")
        parts.append(value.encode())
    parts.append(sep)
    parts.append(('Content-Disposition: form-data; name="fileName"; filename="%s"'
                  % os.path.basename(path)).encode())
    parts.append(b"Content-Type: application/octet-stream")
    parts.append(b"")
    body = b"\r\n".join(parts) + b"\r\n" + blob + b"\r\n" + sep + b"--\r\n"

    req = urllib.request.Request(
        sw.host + "/cgi-bin/httpupload.cgi", data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary,
                 "Content-Length": str(len(body)), **sw._headers()})
    # A 13MB write to an embedded switch is slow; do not give up early.
    #
    # The CGI answers 404 on a SUCCESSFUL upload, so this cannot raise on a
    # non-2xx the way a sane client would - the caller checks the device's own
    # file_dualStatus instead. Only a transport failure is a real failure here.
    try:
        with sw.opener.open(req, timeout=600) as r:
            return r.status, r.read().decode("utf-8", "replace")[:300]
    except urllib.error.HTTPError as e:
        return e.code, "(HTTP %d - expected on this firmware; verify via file_dualStatus)" % e.code


def wait_for_completion(sw, attempts=90):
    """Poll the switch's own upload status until it stops saying 'uploading'."""
    for _ in range(attempts):
        try:
            st = sw.get("file_http_downloadStatus").get("data", {})
        except Exception as e:
            print("   status read failed (%s), retrying" % str(e)[:60])
            time.sleep(5)
            continue
        status = st.get("status", "")
        print("   status: %s" % json.dumps(st)[:160])
        if status and status != "uploading":
            return st
        time.sleep(5)
    return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image_file")
    ap.add_argument("--image", type=int, choices=(1, 2), required=True,
                    help="destination slot; write to the one that is NOT active")
    ap.add_argument("--activate", action="store_true",
                    help="set next boot to the slot just written (does not reboot)")
    args = ap.parse_args()

    sw = MS510()
    sw.login(os.environ["MS510_PASSWORD"])
    try:
        before = sw.get("file_dualStatus").get("data", {}).get("status", [{}])[0]
        print("  before: img1=%s img2=%s active=%s next=%s" % (
            before.get("img1Ver"), before.get("img2Ver"),
            before.get("curAct"), before.get("nextAct")))

        if before.get("curAct") == "image%d" % args.image:
            raise SystemExit("refusing to overwrite the RUNNING image (image%d)" % args.image)

        print("  uploading %s (%d bytes) into image%d ..." % (
            args.image_file, os.path.getsize(args.image_file), args.image))
        code, reply = upload(sw, args.image_file, args.image)
        print("  upload HTTP %s: %s" % (code, reply.replace("\n", " ")[:160]))

        wait_for_completion(sw)

        after = sw.get("file_dualStatus").get("data", {}).get("status", [{}])[0]
        print("  after : img1=%s img2=%s active=%s next=%s" % (
            after.get("img1Ver"), after.get("img2Ver"),
            after.get("curAct"), after.get("nextAct")))

        if args.activate:
            # file_dualStatus is READ-ONLY - its page is a refresh button and
            # nothing else. The write lives on file_dualConf, which takes the
            # slot as imgName (0-based) plus imgActive as a checkbox.
            print("  setting next boot to image%d ..." % args.image)
            print("   ->", json.dumps(sw.set("file_dualConf",
                                             {"imgName": str(args.image - 1),
                                              "imgActive": "on"}))[:160])
            final = sw.get("file_dualStatus").get("data", {}).get("status", [{}])[0]
            print("  next boot is now: %s" % final.get("nextAct"))
            print("  VERIFY WITH THE CLI before rebooting: `show bootvar` should mark the")
            print("  new slot with '*'. The web UI's nextAct field has agreed while the")
            print("  switch went on to boot the other image anyway.")
    finally:
        sw.logout()


if __name__ == "__main__":
    main()
