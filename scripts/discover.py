"""Read-only schema discovery against the PR60X.

Auth sequence (verified 2026-08-31):
  1. GET /                       -> sets the lhttpdsid session cookie
  2. POST /socketCommunication   -> login {username,password} -> result.token
                                    (REQUIRES the cookie; without it: -32602)
  3. subsequent calls            -> cookie + "Security: <token>" header

Calls every get* method with empty params and records the reply. Nothing
here mutates the device.

Usage:  PR60X_PASSWORD=... python discover.py
Output: discovery.json
"""
import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("PR60X_HOST", "https://192.168.1.1")
CTX = ssl._create_unverified_context()

SKIP = {
    "getPacketCapture",
    "getSpeedTest",
    "getSpeedTestHistory",
}


class PR60X:
    def __init__(self, host=HOST):
        self.host = host
        self.token = None
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=CTX),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def prime(self):
        """GET / to obtain lhttpdsid. Required before login."""
        req = urllib.request.Request(self.host + "/")
        with self.opener.open(req, timeout=15) as r:
            return r.status

    def call(self, method, params=None, timeout=30, send_cookie=True):
        payload = {"jsonrpc": "2.0", "id": 1,
                   "method": method, "params": params or {}}
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Security"] = self.token
        req = urllib.request.Request(
            self.host + "/socketCommunication",
            data=json.dumps(payload).encode(),
            headers=headers, method="POST")
        opener = self.opener if send_cookie else urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=CTX))
        try:
            with opener.open(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except ValueError:
                return {"error": {"code": e.code, "message": raw[:200]}}

    def login(self, password, username="admin"):
        self.prime()
        reply = self.call("login",
                          {"username": username, "password": password})
        if "error" in reply and reply["error"].get("code"):
            raise SystemExit("login failed: %r" % (reply["error"],))
        self.token = (reply.get("result") or {}).get("token")
        if not self.token:
            raise SystemExit("no token: %r" % (reply,))
        return self.token

    def logout(self):
        if self.token:
            try:
                self.call("logout")
            except Exception:
                pass
            self.token = None


def main():
    pw = os.environ.get("PR60X_PASSWORD")
    if not pw:
        raise SystemExit("set PR60X_PASSWORD")

    methods = [m.strip() for m in open("methods.txt") if m.strip()]
    targets = sorted(m for m in methods
                     if m.startswith("get") and m not in SKIP)

    r = PR60X()
    r.login(pw)
    sys.stderr.write("logged in\n")

    # Does the token alone suffice, or is the cookie required on every call?
    # Determines whether the Go client needs a cookie jar.
    probe = r.call("getDeviceInfo", send_cookie=False)
    cookie_required = bool(probe.get("error", {}).get("code"))
    sys.stderr.write("cookie required on authed calls: %s (%s)\n\n"
                     % (cookie_required, json.dumps(probe)[:120]))

    out = {"_meta": {"cookie_required_on_authed_calls": cookie_required}}
    ok = err = 0
    try:
        for m in targets:
            reply = r.call(m)
            if "error" in reply and reply["error"].get("code"):
                out[m] = {"error": reply["error"]}
                err += 1
                mark = "ERR %s" % reply["error"].get("code")
            else:
                out[m] = {"result": reply.get("result")}
                ok += 1
                mark = "ok"
            sys.stderr.write("%-38s %s\n" % (m, mark))
    finally:
        r.logout()

    with open("discovery.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    sys.stderr.write("\n%d methods: %d ok, %d err -> discovery.json\n"
                     % (len(targets), ok, err))


if __name__ == "__main__":
    main()
