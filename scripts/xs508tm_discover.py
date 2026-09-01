"""Read-only discovery sweep of a NETGEAR XS-series smart switch.

Walks the route table extracted from the switch's own UI bundle and GETs
everything that is safe to read, recording each response. The output is the
input to three things: pinning the exporter's types, transferring live config
into Terraform, and reviewing the configuration itself.

Nothing here mutates the switch. Routes are filtered three ways:
  * only GET is ever issued
  * any route whose name or path suggests a state change is skipped outright
  * routes taking :path or ?query parameters are skipped, since guessing an
    argument is how you accidentally reset something

Usage:
    XS508TM_PASSWORD=... python xs508tm_discover.py [host]
Output:
    xs508tm_discovery.json
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import http.cookiejar

HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("XS508TM_HOST", "http://192.168.1.223")
ROUTES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xs508tm_routes.json")

# Anything matching these is never requested, even via GET. A switch is not a
# thing to poke speculatively - some vendors action a GET on these.
DANGEROUS = re.compile(
    r"reset|reboot|clear|erase|factory|delete|remove|update|upload|download|"
    r"export|import|save|apply|activate|initialise|initialize|logout|"
    r"file_management|registration",
    re.IGNORECASE,
)


def load_routes():
    with open(ROUTES_FILE, encoding="utf-8") as f:
        routes = json.load(f)
    safe, skipped = {}, {}
    for name, path in routes.items():
        if DANGEROUS.search(name) or DANGEROUS.search(path):
            skipped[name] = (path, "state-changing name")
        elif ":" in path or "?" in path:
            skipped[name] = (path, "needs parameters")
        elif name == "login":
            skipped[name] = (path, "handled separately")
        else:
            safe[name] = path
    return safe, skipped


class Switch:
    def __init__(self, host):
        self.host = host
        self.token = None
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def login(self, username, password):
        # Prime for the lhttpdsid cookie, exactly as the web UI does.
        self.opener.open(urllib.request.Request(self.host + "/"), timeout=15).close()
        payload = {"login": {"username": username, "password": password}}
        req = urllib.request.Request(
            self.host + "/api/v1/login", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with self.opener.open(req, timeout=20) as r:
            body = json.load(r)
        tok = (body.get("login") or {}).get("token")
        if not tok:
            raise SystemExit("login failed: %s" % json.dumps(body)[:200])
        self.token = tok
        return tok

    def get(self, path, timeout=20):
        req = urllib.request.Request(
            self.host + "/api/v1/" + path,
            headers={"Authorization": "Bearer " + self.token})
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"_raw": raw[:300]}
        except Exception as e:
            return 0, {"_error": "%s: %s" % (type(e).__name__, str(e)[:160])}

    def logout(self):
        if not self.token:
            return
        try:
            req = urllib.request.Request(
                self.host + "/api/v1/logout", data=b"{}",
                headers={"Authorization": "Bearer " + self.token,
                         "Content-Type": "application/json"}, method="POST")
            self.opener.open(req, timeout=10).close()
        except Exception:
            pass
        self.token = None


def main():
    pw = os.environ.get("XS508TM_PASSWORD")
    if not pw:
        raise SystemExit("set XS508TM_PASSWORD")

    safe, skipped = load_routes()
    print("routes: %d safe to GET, %d skipped" % (len(safe), len(skipped)), file=sys.stderr)

    sw = Switch(HOST)
    sw.login(os.environ.get("XS508TM_USERNAME", "admin"), pw)
    print("logged in to %s" % HOST, file=sys.stderr)

    out, ok, err = {}, 0, 0
    try:
        for name in sorted(safe):
            path = safe[name]
            status, body = sw.get(path)
            # The switch wraps every reply as {"resp": {...}, "<key>": payload}.
            # Keep the payload; keep resp only when it signals a problem.
            entry = {"route": path, "status": status}
            if isinstance(body, dict):
                resp = body.get("resp") or {}
                payload = {k: v for k, v in body.items() if k != "resp"}
                if resp.get("respCode") not in (0, None):
                    entry["resp"] = resp
                entry["data"] = payload if payload else None
            else:
                entry["data"] = body
            out[name] = entry
            if status == 200 and entry.get("resp") is None:
                ok += 1
                mark = "ok"
            else:
                err += 1
                mark = "HTTP %s" % status
            print("  %-46s %s" % (name, mark), file=sys.stderr)
            time.sleep(0.25)
    finally:
        sw.logout()

    out["_meta"] = {"host": HOST, "skipped": {k: v[1] for k, v in skipped.items()}}
    with open("xs508tm_discovery.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("\n%d ok, %d error -> xs508tm_discovery.json" % (ok, err), file=sys.stderr)


if __name__ == "__main__":
    main()
