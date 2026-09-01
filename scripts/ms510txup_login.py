"""Authenticate to a NETGEAR MS510TXUP and read from its CGI API.

Four mechanisms have to be reproduced, all lifted from the switch's own JS.
The last one is the reason this took several passes to get working.

  urlParamHash()  every URL carries &bj4=md5(<everything after the ?>).
                  An unsigned request is rejected with HTTP 400 - note 400,
                  not 401, so it reads like a malformed URL rather than a
                  missing signature.

  encode()        the password is never sent in clear. It is padded into a
                  320-len(pw) character string of random alphanumerics, with
                  the password's characters placed IN REVERSE at every 7th
                  position, and its length encoded as a tens digit at index
                  123 and a ones digit at index 289. Obfuscation, not
                  encryption - but it has to be reproduced exactly.

  the handshake   POST cgi/set.cgi?cmd=home_loginAuth returns an authId. That
                  is NOT a session. cgi/set.cgi?cmd=home_loginStatus is then
                  polled with that authId until it answers
                  {"data":{"status":"ok","sess":...}}. It genuinely returns a
                  non-ok status on the first poll, so the loop is required.

  X-CSRF-XSID     the real authorization gate, and the reason authenticated
                  calls kept returning 404 with a valid-looking session.

                  `sess` is not a session token. login.html base64-decodes it
                  into three concatenated fields:

                      tabid   = sess[0:32]     32-char session id
                      expo    = sess[32:37]    RSA public exponent, "10001"
                      modulus = sess[37:]      1024-bit RSA modulus, hex

                  It then DELETES the tabid cookie and sends, on every
                  subsequent request, the header

                      X-CSRF-XSID: base64(RSA_PKCS1v15(tabid, pubkey))

                  Without it the switch answers 404 - not 401, not 403 - so
                  the failure is indistinguishable from a wrong URL, which is
                  what sent several passes of this work looking for the wrong
                  thing. The signature (bj4) is checked first and separately:
                  an unsigned request is a 400.
"""
import base64
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


# PKCS#1 v1.5 type-2 framing bytes, and the NUL the sess blob is padded
# with. Built from ordinals rather than written as escapes so the values
# survive being edited through a shell heredoc.
NUL = chr(0)
PKCS1_HEADER = bytes([0x00, 0x02])
PKCS1_SEP = bytes([0x00])


def pkcs1_v15_encrypt(message: bytes, modulus: int, exponent: int) -> bytes:
    """RSA encrypt with PKCS#1 v1.5 type-2 padding - jsbn's rsa.encrypt().

    Reimplemented rather than pulled from a library so these scripts stay
    stdlib-only. Type 2 padding is:

        0x00 || 0x02 || PS (>= 8 random NON-ZERO bytes) || 0x00 || M
    """
    k = (modulus.bit_length() + 7) // 8
    if len(message) > k - 11:
        raise ValueError("message too long for a %d-bit key" % modulus.bit_length())

    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)[0]
        if b:  # PS must contain no zero bytes; a zero terminates the padding
            ps.append(b)

    em = PKCS1_HEADER + bytes(ps) + PKCS1_SEP + message
    c = pow(int.from_bytes(em, "big"), exponent, modulus)
    return c.to_bytes(k, "big")


def parse_sess(sess_b64: str):
    """Split the login `sess` blob into (tabid, exponent, modulus)."""
    raw = base64.b64decode(sess_b64 + "==").decode("latin-1").rstrip(NUL)
    tabid = raw[0:32]
    exponent = int(raw[32:37], 16)
    modulus = int(raw[37:], 16)
    return tabid, exponent, modulus


class LoginError(RuntimeError):
    pass


class MS510:
    def __init__(self, host=HOST):
        self.host = host
        self.sess = None
        self.tabid = None
        self.exponent = None
        self.modulus = None
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def _url(self, path):
        sep = "&" if "?" in path else "?"
        return sign("%s/%s%sdummy=%d" % (self.host, path, sep, int(time.time() * 1000)))

    def _headers(self):
        # Not a cookie: the UI deletes the tabid cookie and authenticates every
        # request with an RSA-encrypted copy of the tabid instead. The padding
        # is randomised, so this is a fresh value per request by design.
        if not self.tabid:
            return {}
        token = pkcs1_v15_encrypt(self.tabid.encode(), self.modulus, self.exponent)
        return {"X-CSRF-XSID": base64.b64encode(token).decode()}

    def _request(self, path, data=None):
        headers = self._headers()
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self._url(path), data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
        with self.opener.open(req, timeout=25) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            return {"_raw": raw[:400]}

    def login(self, password, poll_attempts=15):
        # Touch the login page first; it is also what the UI does.
        self.opener.open(urllib.request.Request(
            sign("%s/login.html?aj4=%d" % (self.host, int(time.time() * 1000)))), timeout=20).close()

        body = urllib.parse.urlencode({"pwd": encode(password), "actKeyText": ""}).encode()
        res = self._request("cgi/set.cgi?cmd=home_loginAuth", body)
        if res.get("status") != "ok" or not res.get("authId"):
            raise LoginError("loginAuth rejected: %s" % json.dumps(res)[:300])
        auth_id = res["authId"]

        # Poll home_loginStatus. The switch answers a non-ok status until the
        # authentication actually completes, so this is a real loop.
        for _ in range(poll_attempts):
            body = urllib.parse.urlencode({"authId": auth_id}).encode()
            res = self._request("cgi/set.cgi?cmd=home_loginStatus", body)
            data = res.get("data") or {}
            status = data.get("status")
            if status == "ok":
                if not data.get("sess"):
                    raise LoginError("login reported ok but returned no session token")
                self.sess = data["sess"]
                self.tabid, self.exponent, self.modulus = parse_sess(self.sess)
                return data
            if status == "fail":
                raise LoginError("login failed: %s" % data.get("failReason", "(no reason given)"))
            time.sleep(1)
        raise LoginError("login never completed after %d polls" % poll_attempts)

    def get(self, cmd):
        return self._request("cgi/get.cgi?cmd=" + cmd)

    def set(self, cmd, fields):
        return self._request("cgi/set.cgi?cmd=" + cmd, urllib.parse.urlencode(fields).encode())

    def logout(self):
        try:
            self._request("cgi/set.cgi?cmd=home_logout", b"")
        except Exception:
            pass
        self.sess = None


if __name__ == "__main__":
    sw = MS510()
    print("  login:", json.dumps(sw.login(os.environ["MS510_PASSWORD"]))[:200])
    print("  tabid:", sw.tabid, " rsa:", sw.modulus.bit_length(), "bit, e =", sw.exponent)
    for cmd in ("home_sts", "sys_info", "lldp_neighbor", "log_remote", "sys_dnsConf"):
        try:
            print("\n  %-14s %s" % (cmd, json.dumps(sw.get(cmd))[:300]))
        except Exception as e:
            print("\n  %-14s ERR %s" % (cmd, e))
    sw.logout()
