package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"netgear-tools/internal/xs508tm"
)

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

// pushMS510TXUP installs the cert over root SSH once sw1 is rooted (mechanism in
// progress separately - gated off by default in devices.go). The web server on
// this switch serves /mnt/ssh/lighttpd_ssl.pem, which its polld rebuilds from
// ssl_cert.pem + ssl_key.pem when HTTPS admin-enable is toggled. Over root SSH
// the equivalent is to write both source files and then rebuild the combined
// PEM and restart lighttpd directly.
//
// [VERIFY] sw1 root is NOT confirmed yet, so the apply command below is a best
// guess at the on-box rebuild+restart and has never run against the device.
// Confirm the real paths and the init script name before enabling sw1:
//   - is the combined file /mnt/ssh/lighttpd_ssl.pem and is it cert THEN key?
//   - is lighttpd restarted via `/etc/init.d/lighttpd restart`, or does polld
//     only pick the new cert up on an HTTPS admin-enable toggle?
//
// Until then this function is wired but unreachable (SW1_ENABLED=false).
func pushMS510TXUP(t sshTarget) pushFunc {
	return func(ctx context.Context, certPEM, keyPEM []byte) error {
		return sshCertPush{
			target: t,
			files: []sshFile{
				{path: "/mnt/ssh/ssl_cert.pem", mode: "600", content: certPEM},
				{path: "/mnt/ssh/ssl_key.pem", mode: "600", content: keyPEM},
			},
			// [VERIFY]/TODO: exact rebuild+restart for this firmware. The
			// combined file the web server actually serves is
			// /mnt/ssh/lighttpd_ssl.pem (cert then key); rebuild it and bounce
			// lighttpd. Replace once validated against a rooted sw1.
			apply: "cat /mnt/ssh/ssl_cert.pem /mnt/ssh/ssl_key.pem > /mnt/ssh/lighttpd_ssl.pem && /etc/init.d/lighttpd restart",
		}.run(ctx)
	}
}
