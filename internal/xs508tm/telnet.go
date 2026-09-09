package xs508tm

// Root telnet cert install for the XS508TM.
//
// # Why telnet and not SSH
//
// The switch's admin SSH lands in the FASTPATH CLI (libsshpam), not a shell, so
// there is no SSH file-write path. Root instead comes from a modified firmware
// that leaves utelnetd listening on :2323 (gated by TELNET_ENABLED=Y in
// /mnt/fastpath/debug_config) with a baked-in root password - a real /bin/sh.
// That is the transport this file speaks. It NEVER touches the Broadcom diag
// console (devshell / /tmp/consolepipe / 127.0.0.1:2222), which watchdog-reboots
// the box; the only endpoint here is the FASTPATH utelnetd root shell on :2323.
//
// # What it installs, and where
//
// lighttpd serves ssl.pemfile = /mnt/fastpath/lighttpd/ssl/https_cert.cer, a
// COMBINED file whose contents are the private KEY then the leaf+chain (verified
// on the running unit, 2026-09-08). The lighttpdMon supervisor also references
// the split https_cert.pem (cert) and https_key.key (key) and rebuilds the .cer
// from them, so all three are written to stay consistent no matter which the
// supervisor treats as source of truth:
//
//	https_cert.pem = leaf+chain
//	https_key.key  = private key
//	https_cert.cer = key THEN leaf+chain   (the pemfile lighttpd loads)
//
// # Reload
//
// lighttpd is 1.4.65 - too old for SIGUSR1 graceful cert reload (1.4.72+) - so a
// restart is required. lighttpdMon respawns lighttpd whenever it is absent (~17s
// poll, measured), and does NOT regenerate a self-signed cert when a valid pair
// is present. To avoid the supervisor's poll latency the daemon is validated,
// killed, and immediately re-spawned by hand (mirroring the WAX630E runbook); the
// supervisor then simply sees it already running. The switch's data plane is in
// hardware (switchdrvr), so bouncing lighttpd only blips the management web UI.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// xs508 on-box cert paths (see file header).
const (
	xsCertPEM = "/mnt/fastpath/lighttpd/ssl/https_cert.pem" // leaf+chain
	xsKeyPEM  = "/mnt/fastpath/lighttpd/ssl/https_key.key"  // private key
	xsCombine = "/mnt/fastpath/lighttpd/ssl/https_cert.cer" // key THEN leaf+chain (ssl.pemfile)
	xsLighttp = "/usr/local/sbin/lighttpd"
	xsConf    = "/etc/lighttpd/config/lighttpd.conf"
)

// xsReload validates the new config, kills the running lighttpd, and re-spawns
// it. `;` (not `&&`) sequences the kill->respawn so a kill that matched nothing
// still leads to a spawn. The ps|grep|awk finds lighttpd's PID (the box has no
// pidof); the [l] bracket keeps grep from matching its own line, and "-f"
// distinguishes lighttpd from the lighttpdMon supervisor.
const xsReload = xsLighttp + " -t -f " + xsConf + " && " +
	"kill $(ps w | grep '[l]ighttpd -f' | awk '{print $1}') 2>/dev/null; sleep 1; " +
	xsLighttp + " -f " + xsConf

// telnet control bytes.
const (
	iac  = 255
	dont = 254
	doo  = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240
)

// TelnetPushCert installs certPEM (leaf+chain) and keyPEM onto the XS508TM over
// its root telnet shell on addr (host:port), authenticating as root with
// password. It writes the three cert files and restarts lighttpd. All file
// content crosses the wire base64-encoded and is decoded on the box with
// `openssl base64 -d` (busybox here has openssl but no base64/printf), which
// sidesteps every newline/quoting hazard of shipping PEM through a line shell.
func TelnetPushCert(addr, password string, certPEM, keyPEM []byte, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("telnet dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tc := &telnetConn{conn: conn}
	if err := tc.login(password); err != nil {
		return err
	}

	// combined pemfile is key THEN leaf+chain (matches the on-box layout).
	combined := append(append(append([]byte{}, keyPEM...), '\n'), certPEM...)
	for _, f := range []struct {
		path    string
		content []byte
	}{
		{xsCertPEM, certPEM},
		{xsKeyPEM, keyPEM},
		{xsCombine, combined},
	} {
		if err := tc.writeFile(f.path, f.content); err != nil {
			return fmt.Errorf("write %s: %w", f.path, err)
		}
	}

	if code, out, err := tc.run(xsReload); err != nil {
		return fmt.Errorf("reload lighttpd: %w", err)
	} else if code != 0 {
		return fmt.Errorf("reload lighttpd: exit %d: %s", code, out)
	}
	return nil
}

// telnetConn wraps the raw connection with telnet option handling and a small
// read buffer of already-decoded (IAC-stripped) bytes.
type telnetConn struct {
	conn net.Conn
	buf  []byte // decoded bytes not yet consumed by expect()
	seq  int
}

// b64ChunkLen bounds each base64 line put on the wire. The device's telnet shell
// runs in canonical (line) mode, whose input buffer caps a single line (MAX_CANON
// / N_TTY, ~4KB) - a full cert's base64 (~7.6KB) on one line is silently
// truncated, dropping the trailing completion marker. So content is streamed as
// many short appended lines. 512 is a multiple of 4, so every chunk is itself
// valid base64 (no split mid-quantum), and `openssl base64 -d` reassembles the
// multi-line stream.
const b64ChunkLen = 512

// writeFile writes content to path on the device by streaming its base64 in
// short appended chunks to a temp file, then decoding that with openssl. See
// b64ChunkLen for why the content cannot go in a single command.
func (t *telnetConn) writeFile(path string, content []byte) error {
	b64 := base64.StdEncoding.EncodeToString(content)
	tmp := path + ".b64.tmp"
	redir := "> '" + tmp + "'" // first chunk truncates; the rest append.
	for i := 0; i < len(b64); i += b64ChunkLen {
		end := i + b64ChunkLen
		if end > len(b64) {
			end = len(b64)
		}
		if code, out, err := t.run("echo '" + b64[i:end] + "' " + redir); err != nil {
			return err
		} else if code != 0 {
			return fmt.Errorf("stream chunk: exit %d: %s", code, out)
		}
		redir = ">> '" + tmp + "'"
	}
	if code, out, err := t.run("openssl base64 -d -in '" + tmp + "' > '" + path + "' && rm -f '" + tmp + "'"); err != nil {
		return err
	} else if code != 0 {
		return fmt.Errorf("decode: exit %d: %s", code, out)
	}
	return nil
}

// login walks the login: / Password: prompts as root, then synchronises to the
// shell prompt by running a no-op through run().
func (t *telnetConn) login(password string) error {
	if err := t.expect("login:", 20*time.Second); err != nil {
		return fmt.Errorf("waiting for login prompt: %w", err)
	}
	if err := t.send("root\r\n"); err != nil {
		return err
	}
	if err := t.expect("assword", 15*time.Second); err != nil {
		return fmt.Errorf("waiting for password prompt: %w", err)
	}
	if err := t.send(password + "\r\n"); err != nil {
		return err
	}
	// Sync to the shell: run() drains everything up to its own end marker, so a
	// bad password (no shell, no marker) surfaces here as a timeout rather than
	// derailing the first real command.
	if _, _, err := t.run("true"); err != nil {
		return fmt.Errorf("login as root failed (bad password or no shell): %w", err)
	}
	return nil
}

// run executes one command and returns its exit code and captured stdout+stderr.
// It appends `; echo <MK>$?<MK>` and reads until the marker appears with a REAL
// digit between the tokens - which only happens in the command's OUTPUT, never in
// the terminal's echo of the command line (that still shows the literal "$?").
func (t *telnetConn) run(cmd string) (int, string, error) {
	t.seq++
	mk := fmt.Sprintf("Q9x%dcE", t.seq)
	full := cmd + "; echo " + mk + "$?" + mk + "\r\n"
	// Fresh read window for this command (a prior expect() may have left an
	// older, nearer deadline on the connection).
	_ = t.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := t.send(full); err != nil {
		return 0, "", err
	}
	re := regexp.MustCompile(regexp.QuoteMeta(mk) + `([0-9]+)` + regexp.QuoteMeta(mk))
	// Read until the completion marker with a digit shows up.
	for {
		if m := re.FindSubmatchIndex(t.buf); m != nil {
			code := 0
			for _, c := range t.buf[m[2]:m[3]] {
				code = code*10 + int(c-'0')
			}
			out := string(t.buf[:m[0]])
			t.buf = t.buf[m[1]:]
			// Strip the echoed command line if present (up to first newline).
			if i := strings.IndexByte(out, '\n'); i >= 0 {
				out = out[i+1:]
			}
			return code, strings.TrimRight(out, "\r\n"), nil
		}
		if err := t.fill(); err != nil {
			return 0, "", err
		}
	}
}

// expect reads until sub appears in the decoded stream, discarding it and
// everything before it.
func (t *telnetConn) expect(sub string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	_ = t.conn.SetReadDeadline(deadline)
	for {
		if i := bytes.Index(t.buf, []byte(sub)); i >= 0 {
			t.buf = t.buf[i+len(sub):]
			return nil
		}
		if err := t.fill(); err != nil {
			return err
		}
	}
}

// fill reads one chunk from the wire, answers any telnet negotiation, and
// appends the plain bytes to t.buf.
func (t *telnetConn) fill() error {
	tmp := make([]byte, 4096)
	n, err := t.conn.Read(tmp)
	if n > 0 {
		t.buf = append(t.buf, t.negotiate(tmp[:n])...)
	}
	if err != nil {
		return err
	}
	return nil
}

// negotiate strips telnet IAC sequences and refuses every option (WONT/DONT), so
// the server stops waiting on negotiation and just streams the shell. Suboption
// blocks (SB..SE) are dropped whole.
func (t *telnetConn) negotiate(in []byte) []byte {
	var out, reply []byte
	for i := 0; i < len(in); {
		if in[i] == iac && i+1 < len(in) {
			cmd := in[i+1]
			switch cmd {
			case doo, dont, will, wont:
				if i+2 < len(in) {
					opt := in[i+2]
					switch cmd {
					case doo:
						reply = append(reply, iac, wont, opt)
					case will:
						reply = append(reply, iac, dont, opt)
					}
					i += 3
					continue
				}
				i += 2
				continue
			case sb:
				j := i + 2
				for j+1 < len(in) && !(in[j] == iac && in[j+1] == se) {
					j++
				}
				i = j + 2
				continue
			default:
				i += 2
				continue
			}
		}
		out = append(out, in[i])
		i++
	}
	if len(reply) > 0 {
		_, _ = t.conn.Write(reply)
	}
	return out
}

func (t *telnetConn) send(s string) error {
	_, err := t.conn.Write([]byte(s))
	return err
}
