package xs508tm

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// The REST API exposes per-port maxFrmsz read-only. Every write shape the UI
// bundle suggests - the whole object echoed back, a single port, minimal keys,
// with and without the fields only the mock fixtures carry - is refused with
// errCode 255, while an echo of igmp_snpg_cfg in the same session succeeds. So
// the frame size is readable over REST and settable only over the SSH CLI,
// which is the same conclusion the firmware upgrade path reached.
//
// The CLI calls it `mtu`, accepts 1500-9198 (not 9216), and writes only to the
// running config - so a change that is not followed by `write memory` is lost
// at the next reboot.

// DefaultPortMTU is what a port reports when running-config carries no mtu
// line for it, which is how the switch ships.
const DefaultPortMTU = 1500

// MaxPortMTU is the ceiling the CLI advertises for `mtu`.
const MaxPortMTU = 9198

type shellBuffer struct {
	mu   sync.Mutex
	buf  []byte
	last time.Time
}

func (s *shellBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	s.last = time.Now()
	return len(p), nil
}

// drain reads until the switch has been quiet for idle. The CLI gives no
// machine-readable end-of-output marker and its prompt changes with the config
// context, so quiet is the only reliable signal that it has finished talking.
func (s *shellBuffer) drain(idle, limit time.Duration) string {
	start := time.Now()
	for {
		s.mu.Lock()
		quiet := time.Since(s.last)
		if quiet >= idle || time.Since(start) > limit {
			out := string(s.buf)
			s.buf = nil
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(150 * time.Millisecond)
	}
}

func (s *shellBuffer) touch() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
}

// CLI is an interactive shell on the switch.
type CLI struct {
	client *ssh.Client
	sess   *ssh.Session
	stdin  interface{ Write([]byte) (int, error) }
	out    *shellBuffer
}

func (c *Client) sshHost() (string, error) {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q is not a URL: %w", c.endpoint, err)
	}
	h := u.Hostname()
	if h == "" {
		return "", fmt.Errorf("no host in endpoint %q", c.endpoint)
	}
	return h + ":22", nil
}

// DialCLI opens an SSH shell and puts it in enable mode with paging off.
func (c *Client) DialCLI() (*CLI, error) {
	addr, err := c.sshHost()
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            c.username,
		Auth:            []ssh.AuthMethod{ssh.Password(c.password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	// Deliberately no KeyExchanges/Ciphers/HostKeyAlgorithms overrides. These
	// fields are not additive: setting one replaces Go's defaults entirely
	// rather than extending them, so "adding legacy algorithms for old
	// firmware" silently removes every modern one. This switch offers
	// rsa-sha2-512/256 and negotiates fine on the defaults.

	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh to %s: %w", addr, err)
	}
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	buf := &shellBuffer{last: time.Now()}
	sess.Stdout = buf
	sess.Stderr = buf
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	// A tall terminal plus `terminal length 0` keeps the pager out of the way.
	if err := sess.RequestPty("vt100", 1200, 220, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	cli := &CLI{client: client, sess: sess, stdin: stdin, out: buf}
	cli.out.drain(3*time.Second, 30*time.Second) // banner
	cli.Send("enable", 3*time.Second)
	cli.Send("terminal length 0", 3*time.Second)
	return cli, nil
}

func (c *CLI) Send(cmd string, idle time.Duration) string {
	c.out.touch()
	_, _ = c.stdin.Write([]byte(cmd + "\n"))
	return c.out.drain(idle, 120*time.Second)
}

// Answer replies to the CLI's single-character y/n prompts, which take no
// newline - sending one gets it echoed as a second, unwanted command.
func (c *CLI) Answer(ch string, idle time.Duration) string {
	c.out.touch()
	_, _ = c.stdin.Write([]byte(ch))
	return c.out.drain(idle, 120*time.Second)
}

func (c *CLI) Close() {
	if c.sess != nil {
		_ = c.sess.Close()
	}
	if c.client != nil {
		_ = c.client.Close()
	}
}

var mtuLine = regexp.MustCompile(`(?m)^\s*mtu\s+(\d+)\s*$`)

func cliRejected(out string) error {
	for _, bad := range []string{"Command not found", "Incomplete command", "Invalid", "not supported"} {
		if strings.Contains(out, bad) {
			return fmt.Errorf("the switch rejected the command: %s", strings.TrimSpace(lastLines(out, 3)))
		}
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n "), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// GetPortMTU reads a port's frame size out of the running config.
func (c *Client) GetPortMTU(port int) (int, error) {
	cli, err := c.DialCLI()
	if err != nil {
		return 0, err
	}
	defer cli.Close()

	out := cli.Send(fmt.Sprintf("show running-config interface 0/%d", port), 5*time.Second)
	if err := cliRejected(out); err != nil {
		return 0, err
	}
	if m := mtuLine.FindStringSubmatch(out); m != nil {
		return strconv.Atoi(m[1])
	}
	// No mtu line at all is the default, not a parse failure: the switch omits
	// settings that match the shipped value.
	return DefaultPortMTU, nil
}

// SetPortMTU sets a port's frame size and saves it. The save is not optional -
// the CLI writes to the running config only, so an unsaved change survives
// until the next reboot and then quietly disappears, which is a miserable way
// to lose a storage network.
func (c *Client) SetPortMTU(port, mtu int) error {
	if mtu < DefaultPortMTU || mtu > MaxPortMTU {
		return fmt.Errorf("mtu %d is outside the %d-%d the CLI accepts", mtu, DefaultPortMTU, MaxPortMTU)
	}
	cli, err := c.DialCLI()
	if err != nil {
		return err
	}
	defer cli.Close()

	cli.Send("configure", 3*time.Second)
	if out := cli.Send(fmt.Sprintf("interface 0/%d", port), 3*time.Second); cliRejected(out) != nil {
		return fmt.Errorf("selecting port 0/%d: %w", port, cliRejected(out))
	}
	if out := cli.Send(fmt.Sprintf("mtu %d", mtu), 5*time.Second); cliRejected(out) != nil {
		return fmt.Errorf("setting mtu %d on port 0/%d: %w", mtu, port, cliRejected(out))
	}
	cli.Send("exit", 2*time.Second)
	cli.Send("exit", 2*time.Second)

	save := cli.Send("write memory", 6*time.Second)
	if strings.Contains(strings.ToLower(save), "y/n") {
		save = cli.Answer("y", 15*time.Second)
	}
	if !strings.Contains(save, "Configuration Saved") && !strings.Contains(save, "successfully") {
		return fmt.Errorf("mtu %d was applied to port 0/%d but the save could not be confirmed, "+
			"so it will be lost at the next reboot: %s", mtu, port, strings.TrimSpace(lastLines(save, 3)))
	}
	return nil
}

// SetAdminPassword changes the switch's admin credential over the CLI.
//
// `password` is a TOP-LEVEL command, available in user mode, and it prompts
// for old / new / confirm in that order with no echo. It is used rather than
// `configure` + `username` because it validates the old password as part of
// the change, so a wrong assumption about the current credential fails safely
// instead of half-applying.
//
// THE PART THAT WILL COST YOU THE CHANGE IF YOU MISS IT:
//
// `password` runs in USER mode, and in user mode `save` is not a command -
// it comes back "% Invalid input detected at '^' marker.". The switch happily
// prints "Password Changed!" and the running config holds the new credential,
// but nothing has been written to NVRAM, so the next reboot silently restores
// the old password. Observed exactly this on 2026-09-05.
//
// So the sequence is deliberately: change, THEN `enable`, THEN `write memory`
// and answer its y/n. The save is verified rather than assumed, because a
// credential that reverts at the next power cut is worse than one that never
// changed - it will be the old one precisely when nobody remembers it.
func (c *Client) SetAdminPassword(oldPassword, newPassword string) error {
	if oldPassword == "" || newPassword == "" {
		return fmt.Errorf("both the old and new password are required")
	}
	cli, err := c.DialCLI()
	if err != nil {
		return err
	}
	defer cli.Close()

	cli.Send("password", 4*time.Second)
	cli.Send(oldPassword, 4*time.Second)
	cli.Send(newPassword, 4*time.Second)
	out := cli.Send(newPassword, 8*time.Second)

	if !strings.Contains(out, "Password Changed") {
		return fmt.Errorf("password was not changed: %s", strings.TrimSpace(lastLines(out, 3)))
	}

	// NVRAM, or the change is lost at the next reboot. Privileged mode first -
	// see the note above.
	cli.Send("enable", 4*time.Second)
	save := cli.Send("write memory", 8*time.Second)
	if strings.Contains(strings.ToLower(save), "y/n") {
		save = cli.Answer("y", 40*time.Second)
	}
	if !strings.Contains(save, "Configuration Saved") && !strings.Contains(save, "successfully") {
		return fmt.Errorf("the password was changed but the save could not be confirmed, "+
			"so it will revert at the next reboot: %s", strings.TrimSpace(lastLines(save, 3)))
	}
	return nil
}
