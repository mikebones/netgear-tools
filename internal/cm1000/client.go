// Package cm1000 reads the NETGEAR CM1000v2 cable modem.
//
// This is the box upstream of everything else - the PR60X's WAN plugs into
// it - and until now it was the one device on the network with no visibility
// at all. It is also the only one whose problems are somebody else's to fix:
// what it reports is the state of the coax plant, and the useful output of
// monitoring it is evidence for an ISP call rather than a setting to change.
//
// THERE IS ALMOST NOTHING TO CONFIGURE HERE, and that is deliberate on the
// vendor's part, not an omission in this package. A cable modem is provisioned
// by the ISP over DOCSIS: channel plan, power targets, service tier and the
// config file all arrive from the CMTS. The web UI exposes little more than a
// reboot, a factory reset and the admin password. So this package reads; there
// is no matching Terraform resource because there is no configuration worth
// declaring.
//
// WHAT IS WORTH WATCHING, in rough order:
//
//   - Uncorrectable codewords. Correctables are the FEC doing its job and are
//     expected in the millions; uncorrectables are data actually lost on the
//     coax, and a rising count is the single clearest signal of a plant fault.
//   - Downstream power, which wants to sit near 0 dBmV and inside -7..+7.
//   - Downstream SNR/MER: QAM256 needs >=33 dB with real margin above that.
//   - Upstream power, which wants to be under about 51 dBmV. A modem shouting
//     into the upstream is compensating for loss and is the usual precursor to
//     dropouts.
//   - Locked channel count. Losing bonded channels cuts throughput long before
//     the connection drops entirely.
package cm1000

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Channel is one bonded RF channel, downstream or upstream, QAM or OFDM.
//
// One struct for all four tables because they overlap heavily and the ones
// that do not simply leave fields zero: upstream carries no SNR or codeword
// counts, and only the DOCSIS 3.1 tables carry a subcarrier range.
type Channel struct {
	Index      int    // position in its table, 1-based
	Locked     bool   // "Locked" vs "Not Locked"
	Modulation string // QAM256, ATDMA, or an OFDM profile list like "0, 1, 2"
	ChannelID  int
	FrequencyH float64 // Hz
	PowerDBMV  float64
	SNRDB      float64 // downstream only; 0 upstream

	// Codeword counters, downstream only. These are the reason to poll this
	// device at all. They are cumulative since the modem last booted and they
	// WRAP - Unerrored on the QAM channels sits near 2^32 and rolls over
	// regularly - so treat them as counters and let rate()/increase() handle
	// the reset rather than reading the absolute value.
	Unerrored     float64
	Correctable   float64
	Uncorrectable float64

	SubcarrierRange string // DOCSIS 3.1 only, e.g. "1588 ~ 2507"
}

// Status is one snapshot of the modem.
type Status struct {
	// Startup is the provisioning sequence: Acquire Downstream Channel,
	// Connectivity State, Boot State, Configuration File, Security, DOCSIS
	// Network Access. Keyed by procedure name.
	Startup map[string]StartupStep

	DownstreamQAM  []Channel
	UpstreamQAM    []Channel
	DownstreamOFDM []Channel
	UpstreamOFDM   []Channel
}

type StartupStep struct {
	Status  string
	Comment string
}

// healthyStartup are the words this firmware uses for a good state. It uses a
// different one per row rather than a single convention.
var healthyStartup = map[string]bool{
	"locked": true, "ok": true, "operational": true,
	"done": true, "success": true, "synchronized": true,
	// Security reads "Enable" with a comment of "BPI+" - that is baseline
	// privacy encryption turned on, which is the good state. "Disabled" here
	// is real and worth noticing.
	"enable": true, "enabled": true,
}

// informationalStartup are rows that carry a MODE, not a health state, and so
// have no failing value to test for. IP Provisioning Mode reads "Honor MDD"
// with a comment of "APM" - that is the modem doing as the CMTS told it, and
// there is no variant of it that means trouble. Reporting these as unhealthy
// because they do not say "OK" would be a permanent false alarm.
var informationalStartup = map[string]bool{
	"ip provisioning mode": true,
}

// OK reports whether a startup step is in a healthy state.
//
// CHECKS BOTH COLUMNS, and that is not belt-and-braces. The firmware does not
// keep health in one place: "Acquire Downstream Channel" puts the FREQUENCY in
// Status ("729000000 Hz") and the word "Locked" in Comment, while
// "Connectivity State" puts "OK" in Status and "Operational" in Comment.
// Testing Status alone marks a perfectly healthy modem as failing on the one
// row that matters most.
func (s StartupStep) OK() bool {
	return s.okWithName("")
}

// OKFor is OK with the row's name, so the informational rows can be
// recognised. Prefer it where the name is to hand.
func (s StartupStep) OKFor(name string) bool { return s.okWithName(name) }

func (s StartupStep) okWithName(name string) bool {
	if informationalStartup[strings.ToLower(strings.TrimSpace(name))] {
		return true
	}
	for _, v := range []string{s.Status, s.Comment} {
		if healthyStartup[strings.ToLower(strings.TrimSpace(v))] {
			return true
		}
	}
	// Configuration File reports the config filename rather than a status
	// word once it has one, e.g. "^1/846CFC3A/TYPE=RES/...". Having a value
	// at all is the success condition; the failure is an empty cell.
	if strings.EqualFold(strings.TrimSpace(name), "configuration file") {
		return strings.TrimSpace(s.Status) != "" || strings.TrimSpace(s.Comment) != ""
	}
	return false
}

type Client struct {
	endpoint string
	username string
	password string
	http     *http.Client

	mu       sync.Mutex
	lastCall time.Time
}

// minInterval paces requests.
//
// THE MODEM SERVES ONE CONNECTION AT A TIME and answers "Connection: close"
// on every response. Two requests in quick succession get the second one
// reset (curl exit 56) rather than queued, which looks exactly like the modem
// being down. Pacing is not politeness here, it is correctness.
const minInterval = 2 * time.Second

func NewClient(endpoint, username, password string) *Client {
	if username == "" {
		username = "admin"
	}
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		username: username,
		password: password,
		// No cookie jar and no session: the modem uses plain HTTP Basic on
		// every request, so there is nothing to keep.
		http: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) get(path string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := time.Until(c.lastCall.Add(minInterval)); d > 0 {
		time.Sleep(d)
	}
	defer func() { c.lastCall = time.Now() }()

	var lastErr error
	// Two attempts. A connection reset here is usually the one-connection
	// limit rather than a real failure, and retrying once costs less than a
	// spurious gap in the metrics.
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(minInterval)
		}
		req, err := http.NewRequest(http.MethodGet, c.endpoint+path, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.username, c.password)
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("%s returned 401 - the modem rejected the admin credentials", path)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s returned %d", path, resp.StatusCode)
		}
		return body, nil
	}
	return nil, fmt.Errorf("%s: %w", path, lastErr)
}

var (
	tableRe = regexp.MustCompile(`(?is)<table[^>]*>(.*?)</table>`)
	rowRe   = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	cellRe  = regexp.MustCompile(`(?is)<t[dh][^>]*>(.*?)</t[dh]>`)
	tagRe   = regexp.MustCompile(`(?s)<[^>]+>`)
	wsRe    = regexp.MustCompile(`\s+`)
)

func cellText(s string) string {
	return strings.TrimSpace(wsRe.ReplaceAllString(tagRe.ReplaceAllString(s, ""), " "))
}

// num pulls the leading number out of a cell, so "729000000 Hz", "1.5 dBmV"
// and "43.8 dB" all work without a per-column unit-stripping rule.
func num(s string) float64 {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) {
		ch := s[end]
		if (ch >= '0' && ch <= '9') || ch == '.' || ((ch == '-' || ch == '+') && end == 0) {
			end++
			continue
		}
		break
	}
	f, err := strconv.ParseFloat(strings.TrimPrefix(s[:end], "+"), 64)
	if err != nil {
		return 0
	}
	return f
}

// DocsisStatus fetches and parses DocsisStatus.asp.
//
// THE PAGE CONTAINS TWO COPIES OF EVERYTHING and only one of them is real.
// Its inline JavaScript defines Init*TagValue() functions holding placeholder
// rows - "In Progress", "Not Synchronized", a 2012 timestamp, a single QAM64
// channel - which look like plausible live readings and are not. The real
// values are emitted server-side as ordinary HTML <tr> rows. Parsing the
// markup rather than the script is deliberate; reading the JS gives a
// confidently wrong answer.
//
// Tables are identified by their column count rather than an id, because the
// ids sit on wrapper elements rather than the tables themselves:
//
//	 3 cols -> startup procedure
//	10 cols -> downstream QAM
//	 6 cols -> upstream (QAM or OFDMA - disambiguated by order)
//	11 cols -> downstream OFDM
func (c *Client) DocsisStatus() (Status, error) {
	body, err := c.get("/DocsisStatus.asp")
	if err != nil {
		return Status{}, err
	}
	st := Status{Startup: map[string]StartupStep{}}

	sixCol := 0
	for _, tm := range tableRe.FindAllStringSubmatch(string(body), -1) {
		rows := rowRe.FindAllStringSubmatch(tm[1], -1)
		if len(rows) < 2 {
			continue
		}
		hdr := cellsOf(rows[0][1])
		switch len(hdr) {
		case 3:
			if !strings.EqualFold(hdr[0], "Procedure") {
				continue
			}
			for _, r := range rows[1:] {
				cs := cellsOf(r[1])
				if len(cs) == 3 {
					st.Startup[cs[0]] = StartupStep{Status: cs[1], Comment: cs[2]}
				}
			}
		case 10:
			st.DownstreamQAM = parseChannels(rows[1:], 10)
		case 11:
			st.DownstreamOFDM = parseChannels(rows[1:], 11)
		case 6:
			// Both upstream tables have six columns. The QAM one is emitted
			// first, the OFDMA one second.
			ch := parseChannels(rows[1:], 6)
			if sixCol == 0 {
				st.UpstreamQAM = ch
			} else {
				st.UpstreamOFDM = ch
			}
			sixCol++
		}
	}
	if len(st.DownstreamQAM) == 0 && len(st.DownstreamOFDM) == 0 {
		return st, fmt.Errorf("DocsisStatus.asp parsed no channel tables - the page layout may have " +
			"changed, or the response was the login page rather than the status page")
	}
	return st, nil
}

func cellsOf(row string) []string {
	ms := cellRe.FindAllStringSubmatch(row, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, cellText(m[1]))
	}
	return out
}

func parseChannels(rows [][]string, cols int) []Channel {
	var out []Channel
	for _, r := range rows {
		cs := cellsOf(r[1])
		if len(cs) != cols {
			continue
		}
		ch := Channel{
			Index:      int(num(cs[0])),
			Locked:     strings.EqualFold(cs[1], "Locked"),
			Modulation: cs[2],
			ChannelID:  int(num(cs[3])),
			FrequencyH: num(cs[4]),
			PowerDBMV:  num(cs[5]),
		}
		switch cols {
		case 10: // downstream QAM
			ch.SNRDB = num(cs[6])
			ch.Unerrored, ch.Correctable, ch.Uncorrectable = num(cs[7]), num(cs[8]), num(cs[9])
		case 11: // downstream OFDM
			ch.SNRDB = num(cs[6])
			ch.SubcarrierRange = cs[7]
			ch.Unerrored, ch.Correctable, ch.Uncorrectable = num(cs[8]), num(cs[9]), num(cs[10])
		}
		out = append(out, ch)
	}
	return out
}

// LockedCount is a convenience for the metric that matters most at a glance:
// losing bonded channels cuts throughput long before the link drops.
func LockedCount(chs []Channel) int {
	n := 0
	for _, c := range chs {
		if c.Locked {
			n++
		}
	}
	return n
}
