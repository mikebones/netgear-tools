package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"netgear-tools/internal/ms510txup"
	"netgear-tools/internal/xs508tm"
)

// firstWorking returns a pushFunc that installs via primary and, ONLY if that
// errors, falls back to fallback. Every device here now has a root path
// (SSH/telnet) as primary; the ones that also have a legacy web path keep it as
// automatic backup. SSH is preferred because it needs no admin web/management
// session, which is what hits the switches' session limits and lockouts (sw1's
// admin is locked out entirely - its SSH path installs the cert regardless). The
// web method runs only when root is unreachable (dial/auth failure), so a
// firmware revert or a downed dropbear degrades to the old behaviour instead of
// failing outright. primaryName/fallbackName are logged so the operator log
// records which mechanism actually served the cert.
func firstWorking(device, primaryName, fallbackName string, primary, fallback pushFunc) pushFunc {
	return func(ctx context.Context, certPEM, keyPEM []byte) error {
		if err := primary(ctx, certPEM, keyPEM); err == nil {
			log.Printf("%s: installed via %s (primary)", device, primaryName)
			return nil
		} else if fallback == nil {
			return fmt.Errorf("%s push failed and no fallback configured: %w", primaryName, err)
		} else {
			log.Printf("%s: %s push failed (%v); falling back to %s", device, primaryName, err, fallbackName)
			if ferr := fallback(ctx, certPEM, keyPEM); ferr != nil {
				return fmt.Errorf("%s failed (%v) and %s fallback failed: %w", primaryName, err, fallbackName, ferr)
			}
			log.Printf("%s: installed via %s (fallback)", device, fallbackName)
			return nil
		}
	}
}

// servedCert dials addr (host:port), completes a TLS handshake, and returns the
// leaf certificate the device presents. Verification is skipped on purpose: the
// point is to read WHICH cert is being served so we can compare fingerprints,
// and these devices start life self-signed, so a verify would just fail before
// we ever get to look.
func servedCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(addr)})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.HandshakeContext(dialCtx); err != nil {
		return nil, err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s presented no certificate", addr)
	}
	return certs[0], nil
}

// --- sw2 (XS508TM): headless REST upload -------------------------------------

// pushXS508TM installs the cert+key over the switch's REST API. The client does
// the whole safety dance itself: disable HTTPS, spool both files, verify a
// matching pair landed, then restore HTTPS - so a failed swap leaves HTTPS off
// rather than wedging lighttpd. See internal/xs508tm/upload.go.
func pushXS508TM(endpoint, username, password string, insecure bool) pushFunc {
	return func(_ context.Context, certPEM, keyPEM []byte) error {
		c, err := xs508tm.NewClient(endpoint, username, password, insecure)
		if err != nil {
			return fmt.Errorf("create xs508tm client: %w", err)
		}
		return c.UploadCertificate(certPEM, keyPEM)
	}
}

// pushXS508TMTelnet installs the cert over the XS508TM's root telnet shell
// (:2323, modified firmware), the PRIMARY sw2 path. It writes the three on-box
// cert files and restarts lighttpd without any admin web session - so it does
// not disable HTTPS, does not consume an admin login, and cannot be locked out.
// It NEVER touches the Broadcom diag console. See internal/xs508tm/telnet.go for
// the paths, the base64 transport, and the reload. The root password comes from
// a mounted secret; addr is host:port.
func pushXS508TMTelnet(addr, password string) pushFunc {
	return func(_ context.Context, certPEM, keyPEM []byte) error {
		return xs508tm.TelnetPushCert(addr, password, certPEM, keyPEM, 45*time.Second)
	}
}

// --- root-SSH file-write devices (PR60X now; MS510TXUP once rooted) ----------

// sshFile is one file to drop over SSH.
type sshFile struct {
	path    string
	mode    string // chmod argument, e.g. "600"
	content []byte
}

// sshCertPush writes a set of files and then runs one apply command, all over a
// single SSH connection. Both the router and (once rooted) sw1 install certs
// this way; only the file paths, the file contents, and the apply command
// differ, so the transport lives here once.
type sshCertPush struct {
	target sshTarget
	files  []sshFile
	apply  string // command run after all files are written
}

type sshTarget struct {
	addr    string // host:port
	user    string
	signer  ssh.Signer
	hostKey ssh.PublicKey // nil => accept any (LAN device, see run)
}

func (p sshCertPush) run(_ context.Context) error {
	cb := ssh.InsecureIgnoreHostKey() //nolint:gosec // LAN appliance; pinned below when a host key is supplied.
	if p.target.hostKey != nil {
		cb = ssh.FixedHostKey(p.target.hostKey)
	}
	cfg := &ssh.ClientConfig{
		User:            p.target.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(p.target.signer)},
		HostKeyCallback: cb,
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", p.target.addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", p.target.addr, err)
	}
	defer client.Close()

	for _, f := range p.files {
		// `cat > path` with the content on stdin - exactly what the shell
		// renewal scripts do, and it sidesteps any quoting of PEM material.
		if err := sshRun(client, "cat > "+f.path, f.content); err != nil {
			return fmt.Errorf("write %s: %w", f.path, err)
		}
		if f.mode != "" {
			if err := sshRun(client, fmt.Sprintf("chmod %s %s", f.mode, f.path), nil); err != nil {
				return fmt.Errorf("chmod %s: %w", f.path, err)
			}
		}
	}
	if p.apply != "" {
		if err := sshRun(client, p.apply, nil); err != nil {
			return fmt.Errorf("apply: %w", err)
		}
	}
	return nil
}

// sshRun runs one command over its own session, feeding stdin if given. A
// session may run only a single command, so each file write and the apply step
// take one each. On failure the command's combined output is folded into the
// error - a bare "Process exited with status 1" is useless when the box is
// remote.
func sshRun(client *ssh.Client, cmd string, stdin []byte) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = bytesReader(stdin)
	}
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("%q: %w (output: %s)", cmd, err, truncateOut(out))
	}
	return nil
}

// pushPR60X mirrors renew-pr60x-cert.sh: lighttpd serves
// /etc/lighttpd/server.pem (key THEN cert, matching ntgr_cert_generate.sh's
// `cat $KEY $CERT > $PEM`), which persists across reboots. Write that plus the
// split key/cert, then restart lighttpd - non-routing and cheap.
func pushPR60X(t sshTarget) pushFunc {
	return func(ctx context.Context, certPEM, keyPEM []byte) error {
		return sshCertPush{
			target: t,
			files: []sshFile{
				{path: "/etc/lighttpd/server.pem", mode: "600", content: concatPEM(keyPEM, certPEM)},
				{path: "/etc/lighttpd/server.key", mode: "600", content: keyPEM},
				{path: "/etc/lighttpd/server.crt", mode: "644", content: certPEM},
			},
			apply: "/etc/init.d/lighttpd restart",
		}.run(ctx)
	}
}

// pushMS510TXUPSSH installs the cert over the MS510TXUP's root dropbear shell
// (:2222, user sshd -> uid 0 on the modified firmware), the PRIMARY sw1 path and
// the one that matters most: sw1's admin is LOCKED OUT, so the web CGI upload
// cannot run at all - this path installs the cert without any admin session.
//
// lighttpd (1.4.79) serves ssl.pemfile = /mnt/ssh/lighttpd_ssl.pem, a combined
// file that is the leaf+chain THEN the key (verified on the unit). polld/the web
// CGI keep the split /mnt/ssh/ssl_cert.pem and ssl_key.pem as the inputs it is
// rebuilt from, so both are written and the combined regenerated the same way
// (cat cert then key). lighttpd is NOT supervised (inittab respawns only sh and
// dropbear), so after validating the new config it is killed and re-spawned by
// hand - the operator's own channel is dropbear, not lighttpd, so bouncing the
// web server never severs the push. The final spawn's fds are redirected so the
// self-daemonising lighttpd does not hold the SSH session open.
func pushMS510TXUPSSH(t sshTarget) pushFunc {
	return func(ctx context.Context, certPEM, keyPEM []byte) error {
		return sshCertPush{
			target: t,
			files: []sshFile{
				{path: "/mnt/ssh/ssl_cert.pem", mode: "644", content: certPEM},
				{path: "/mnt/ssh/ssl_key.pem", mode: "600", content: keyPEM},
			},
			apply: "cat /mnt/ssh/ssl_cert.pem > /mnt/ssh/lighttpd_ssl.pem && " +
				"cat /mnt/ssh/ssl_key.pem >> /mnt/ssh/lighttpd_ssl.pem && " +
				"lighttpd -t -f /etc/lighttpd.conf && " +
				"kill $(pidof lighttpd) 2>/dev/null; sleep 1; " +
				"lighttpd -f /etc/lighttpd.conf </dev/null >/dev/null 2>&1",
		}.run(ctx)
	}
}

// pushWAX630E installs the cert over root SSH, mirroring the WAX630E root-cert
// runbook. Its lighttpd (started with -f /etc/lighttpd_day1.conf) serves a
// SEPARATE pemfile /var/ssl/cert.pem (leaf+chain) and privkey /var/ssl/key.pem,
// which S011nddmp.sh copies at boot from the persistent source /sysconfig/ssl -
// and only leaves alone (rather than regenerating a self-signed pair) when
// /sysconfig/ssl/cert_generated contains the word "extension". So write both
// files to /sysconfig/ssl, rebuild the legacy server.pem (key THEN cert) and the
// cert_generated guard, copy the set to the live /var/ssl, then restart the
// daemon by hand: the stock /etc/init.d/lighttpd is broken (it validates a
// nonexistent /etc/lighttpd/lighttpd.conf), so kill and re-spawn
// /usr/sbin/lighttpd with the day1 conf. The `; sleep 1;` around the kill is
// deliberate (matches the runbook): start-stop-daemon -K exits non-zero when
// nothing was running, which must NOT abort the re-spawn, so those steps are
// sequenced with ; not &&.
func pushWAX630E(t sshTarget) pushFunc {
	return func(ctx context.Context, certPEM, keyPEM []byte) error {
		return sshCertPush{
			target: t,
			files: []sshFile{
				{path: "/sysconfig/ssl/cert.pem", mode: "660", content: certPEM},
				{path: "/sysconfig/ssl/key.pem", mode: "600", content: keyPEM},
			},
			apply: "cat /sysconfig/ssl/key.pem > /sysconfig/ssl/server.pem && " +
				"cat /sysconfig/ssl/cert.pem >> /sysconfig/ssl/server.pem && " +
				`echo "$(date):Cert with extension" > /sysconfig/ssl/cert_generated && ` +
				"cp -f /sysconfig/ssl/cert.pem /sysconfig/ssl/key.pem /sysconfig/ssl/server.pem /sysconfig/ssl/cert_generated /var/ssl/ && " +
				"lighttpd -t -f /etc/lighttpd_day1.conf && " +
				"start-stop-daemon -K -q -x /usr/sbin/lighttpd; sleep 1; " +
				"start-stop-daemon -S -q -b -x /usr/sbin/lighttpd -- -f /etc/lighttpd_day1.conf",
		}.run(ctx)
	}
}

// pushMS510TXUPHTTP installs the cert over the MS510TXUP's own HTTP CGI upload -
// fully headless, no root SSH required. The client POSTs the cert (leaf+chain)
// and the RSA key to the switch's httprootcert.cgi / httpservercert.cgi with the
// X-CSRF-XSID and Referer headers those endpoints demand, then toggles HTTPS
// off->on so polld rebuilds the served PEM. See internal/ms510txup/upload.go.
//
// endpoint MUST be the switch's IP over http:// (e.g. http://192.0.2.2): the
// CNAME login-loops (an HSTS scheme mix), and the client drives the whole
// exchange over port 80, flipping the HTTPS admin flag from there. The admin
// password comes from a mounted secret, never baked in.
func pushMS510TXUPHTTP(endpoint, password string) pushFunc {
	return func(_ context.Context, certPEM, keyPEM []byte) error {
		c, err := ms510txup.NewClient(endpoint, password, false)
		if err != nil {
			return fmt.Errorf("create ms510txup client: %w", err)
		}
		return c.UploadCertificate(certPEM, keyPEM)
	}
}
