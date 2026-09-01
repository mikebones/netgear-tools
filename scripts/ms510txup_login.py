"""Authenticate to a NETGEAR MS510TXUP and read from its CGI API.

Three mechanisms have to be reproduced, all lifted from the switch's own JS:

  urlParamHash()  every URL carries &bj4=md5(<everything after the ?>).
                  Requests without it are rejected.

  encode()        the password is never sent in clear. It is padded into a
                  320-len(pw) character string of random alphanumerics, with
                  the password's characters placed IN REVERSE at every 7th
                  position, and its length encoded as a tens digit at index
                  123 and a ones digit at index 289. Obfuscation, not
                  encryption - but it has to be reproduced exactly.

  cgi/set.cgi?cmd=home_loginAuth   the login endpoint; the reply carries
                  {"data":{"status":"ok","sess":...}} and an authId.
"""
import hashlib
import http.cookiejar
import json
import os
import random
import string
import time
import urllib.parse
import urllib.request

HOST = os.environ.get("MS510_HOST", "http://192.168.1.2")
POSSIBLE = string.ascii_uppercase + string.ascii_lowercase + string.digits


def encode(password: str) -> str:
    """Port of the switch's encode() from js/utility.js."""
    text = []
    ln = len(password)
    lenn = len(password)
    for i in range(1, 320 - len(password) + 1):
        if i % 7 == 0 and ln > 0:
            ln -= 1
            text.append(password[ln])
        elif i == 123:
            text.append("0" if lenn < 10 else str(lenn // 10))
        elif i == 289:
            text.append(str(lenn % 10))
        else:
            text.append(random.choice(POSSIBLE))
    return "".join(text)


def sign(url: str) -> str:
    """Port of urlParamHash(): append &bj4=md5(querystring)."""
    if "?" not in url:
        return url
    qs = url.split("?", 1)[1]
    return url + "&bj4=" + hashlib.md5(qs.encode()).hexdigest()


class MS510:
    def __init__(self, host=HOST):
        self.host = host
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def _url(self, path):
        sep = "&" if "?" in path else "?"
        return sign("%s/%s%sdummy=%d" % (self.host, path, sep, int(time.time() * 1000)))

    def login(self, password):
        # Touch the login page first so the switch issues a session cookie.
        self.opener.open(urllib.request.Request(
            sign("%s/login.html?aj4=%d" % (self.host, int(time.time() * 1000)))), timeout=20).close()
        body = urllib.parse.urlencode({"pwd": encode(password), "actKeyText": ""}).encode()
        req = urllib.request.Request(
            self._url("cgi/set.cgi?cmd=home_loginAuth"), data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with self.opener.open(req, timeout=25) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            return {"_raw": raw[:400]}

    def get(self, cmd):
        req = urllib.request.Request(self._url("cgi/get.cgi?cmd=" + cmd))
        with self.opener.open(req, timeout=25) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            return {"_raw": raw[:400]}

    def logout(self):
        try:
            self.opener.open(urllib.request.Request(
                self._url("cgi/set.cgi?cmd=home_logout"), data=b"", method="POST"), timeout=10).close()
        except Exception:
            pass


if __name__ == "__main__":
    pw = os.environ["MS510_PASSWORD"]
    sw = MS510()
    print("  cookies before:", [c.name for c in sw.jar])
    res = sw.login(pw)
    print("  login reply:", json.dumps(res)[:260])
    print("  cookies after :", [c.name for c in sw.jar])
    for cmd in ("sys_info", "lldp_neighbor", "log_remote", "sys_dnsConf"):
        out = sw.get(cmd)
        print("\n  %-14s %s" % (cmd, json.dumps(out)[:320]))
    sw.logout()
