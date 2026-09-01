"""Authenticate to a NETGEAR WAX630E access point and drive its local API.

The AP shares the PR60X's transport - POST /socketCommunication, lighttpd
lhttpdsid cookie - but authenticates completely differently, and none of it is
in the 27-entry API map the SPA builds, which is why it takes some finding.

  login   POST /socketCommunication with a `time` header (NOT `security`) and
          {"system":{"basicSettings":{"adminName","adminPasswd"}}}.
          status 0 is success. The session token comes back in the `security`
          RESPONSE header; the web UI stores btoa(token) in a non-HttpOnly
          `ssid` cookie and sends atob(cookie) back as the `security` request
          header - so for a non-browser client the response header value IS
          the request header value, with no base64 round trip.

  reads   POST /socketCommunication with `security` and a query-by-example
          body: the JSON shape you want, values left empty. The device fills
          it in. A shape it does not recognise returns err_code 28
          "Invalid configuration" - distinct from status 100, which is the
          not-authenticated redirect the UI turns into a bounce to AP_login.

  /login is NOT this. It is customerLogin - the NETGEAR cloud account, taking
  {email,password} from the marketing modal.

Note the lockout: more than two consecutive bad passwords disables login for a
firmware-chosen interval, reported as err_code 26 with a `time` in minutes.
"""
import datetime
import http.cookiejar
import json
import os
import ssl
import urllib.request

HOST = os.environ.get("WAX630_HOST", "https://192.168.1.136")

# Query-by-example templates lifted from the SPA bundle. These are the exact
# shapes the firmware accepts; an invented one is rejected.
TEMPLATES = {
    "dashboard": {"system": {"basicSettings": {"apName": "", "sysCountryRegion": "", "dhcpClientStatus": ""},
                             "wlanRouterSettings": {"pppoeClientStatus": ""},
                             "monitor": {"ethernetMacAddress": "", "sysVersion": "", "sysCountryRegion": "",
                                         "defaultGateway": "", "defaultGatewayStatus": "", "ipAddress": "",
                                         "DeviceInfo": {"UpTime": ""}, "stats": {"lan": {"traffic": ""}}}}},
    "general": {"system": {"monitor": {"countryList": ""},
                           "basicSettings": {"apName": "", "deviceMode": "", "sysCountryRegion": "", "cloudStatus": ""}}},
    "time": {"system": {"timeSettings": {"timeZone": "", "ntpClientStatus": "", "customNtpServer": "",
                                         "ntpAddr": "", "ntpAddrType": ""}, "monitor": {"currentTime": ""}}},
    "syslog": {"system": {"logSettings": {"syslogStatus": "", "syslogSrvIp": "", "syslogSrvPort": ""}}},
    "stations": {"numberOfStations": ""},
    "radio": {"wlan1Support": []},
}


def _js_time():
    """The UI sends Date.toString() 45 minutes ahead, minus the "(Zone)" part."""
    d = datetime.datetime.now().astimezone() + datetime.timedelta(minutes=45)
    return d.strftime("%a %b %d %Y %H:%M:%S GMT") + d.strftime("%z")


class WAX630E:
    def __init__(self, host=HOST, insecure=True):
        self.host = host
        self.token = None
        ctx = ssl._create_unverified_context() if insecure else None
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar))

    def _post(self, payload, headers):
        h = {"Content-Type": "application/json; charset=UTF-8"}
        h.update(headers)
        req = urllib.request.Request(self.host + "/socketCommunication",
                                     data=json.dumps(payload).encode(),
                                     headers=h, method="POST")
        with self.opener.open(req, timeout=30) as r:
            return dict(r.headers), json.loads(r.read().decode("utf-8", "replace"))

    def login(self, username, password):
        # GET / first for the lhttpdsid cookie, exactly as with the router.
        self.opener.open(urllib.request.Request(self.host + "/"), timeout=25).close()
        hdrs, body = self._post(
            {"system": {"basicSettings": {"adminName": username, "adminPasswd": password}}},
            {"time": _js_time()})
        if str(body.get("status")) != "0":
            raise RuntimeError("login failed: %s" % json.dumps(body)[:300])
        self.token = hdrs.get("security") or hdrs.get("Security")
        if not self.token:
            raise RuntimeError("login reported success but returned no security header")
        return body

    def call(self, payload):
        if not self.token:
            raise RuntimeError("not logged in")
        _, body = self._post(payload, {"security": self.token})
        return body

    def get(self, name):
        return self.call(TEMPLATES[name])

    def set_syslog(self, ip, port=514, enabled=True):
        return self.call({"system": {"logSettings": {
            "syslogStatus": "1" if enabled else "0",
            "syslogSrvIp": ip, "syslogSrvPort": str(port)}}})

    def logout(self):
        if not self.token:
            return
        try:
            req = urllib.request.Request(
                self.host + "/logout", data=b"{}",
                headers={"Content-Type": "application/json; charset=UTF-8",
                         "security": self.token}, method="POST")
            self.opener.open(req, timeout=15).close()
        except Exception:
            pass
        self.token = None


if __name__ == "__main__":
    ap = WAX630E()
    print("  login:", json.dumps(ap.login(os.environ.get("WAX630_USERNAME", "admin"),
                                          os.environ["WAX630_PASSWORD"])))
    for name in ("dashboard", "general", "time", "syslog", "stations", "radio"):
        try:
            print("\n  %-10s %s" % (name, json.dumps(ap.get(name))[:420]))
        except Exception as e:
            print("\n  %-10s ERR %s" % (name, e))
    ap.logout()
