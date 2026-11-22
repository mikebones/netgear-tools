package xs508tm

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- VLAN membership over the SSH CLI ----------------------------------------
//
// NOT YET VERIFIED ON A LIVE SWITCH: written against standard FASTPATH/NETGEAR
// CLI syntax, and the parser is tested on representative `show vlan <id>`
// output only. Verify with a plan + `show vlan` on first use.
//
// Like the MS510 resource it never changes a port's PVID: ports are added as
// tagged members only, so untagged traffic stays where it is.
//
//   vlan database / vlan <id> / vlan name <id> <name> / exit
//   configure / interface 0/<p> / vlan participation include <id>
//                                 vlan tagging <id> / exit ... / exit
//   write memory (y)

// VLAN is a VLAN and its tagged member ports (front-panel numbers).
type VLAN struct {
	ID          int
	Name        string
	TaggedPorts []int
}

var (
	vlanNameLine = regexp.MustCompile(`(?m)^\s*VLAN Name\.*\s*(\S.*?)\s*$`)
	vlanPortLine = regexp.MustCompile(`(?m)^\s*0/(\d+)\s+(Include|Exclude|Autodetect)\s+(Include|Exclude|Autodetect)\s+(Tagged|Untagged)\b`)
	vlanMissing  = regexp.MustCompile(`(?i)(does not exist|not exist|invalid vlan|ERROR)`)
)

// parseShowVLAN reads `show vlan <id>` output. ok is false when the VLAN does not exist.
func parseShowVLAN(id int, out string) (v VLAN, ok bool) {
	if vlanMissing.MatchString(out) && !vlanPortLine.MatchString(out) {
		return VLAN{}, false
	}
	m := vlanNameLine.FindStringSubmatch(out)
	if m == nil && !vlanPortLine.MatchString(out) {
		return VLAN{}, false
	}
	v.ID = id
	if m != nil {
		v.Name = m[1]
	}
	for _, pm := range vlanPortLine.FindAllStringSubmatch(out, -1) {
		port, _ := strconv.Atoi(pm[1])
		if pm[3] == "Include" && pm[4] == "Tagged" {
			v.TaggedPorts = append(v.TaggedPorts, port)
		}
	}
	sort.Ints(v.TaggedPorts)
	return v, true
}

// GetVLAN returns the VLAN, or nil if it does not exist.
func (c *Client) GetVLAN(id int) (*VLAN, error) {
	cli, err := c.DialCLI()
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	out := cli.Send(fmt.Sprintf("show vlan %d", id), 4*time.Second)
	v, ok := parseShowVLAN(id, out)
	if !ok {
		return nil, nil
	}
	return &v, nil
}

func saveConfig(cli *CLI) error {
	save := cli.Send("write memory", 6*time.Second)
	if strings.Contains(strings.ToLower(save), "y/n") {
		save = cli.Answer("y", 15*time.Second)
	}
	if !strings.Contains(save, "Configuration Saved") && !strings.Contains(save, "successfully") {
		return fmt.Errorf("the change was applied but the save could not be confirmed, so it will be lost at the next reboot: %s",
			strings.TrimSpace(lastLines(save, 3)))
	}
	return nil
}

// SetVLAN creates the VLAN if needed, names it, and makes TaggedPorts exactly
// its tagged members (ports dropped from the list are excluded again). PVIDs
// are never touched. The config is saved.
func (c *Client) SetVLAN(v VLAN, previouslyTagged []int) error {
	if v.ID < 2 || v.ID > 4093 {
		return fmt.Errorf("VLAN %d is outside 2-4093 (VLAN 1 is not managed here)", v.ID)
	}
	cli, err := c.DialCLI()
	if err != nil {
		return err
	}
	defer cli.Close()

	cli.Send("vlan database", 3*time.Second)
	if out := cli.Send(fmt.Sprintf("vlan %d", v.ID), 4*time.Second); cliRejected(out) != nil {
		return fmt.Errorf("creating VLAN %d: %w", v.ID, cliRejected(out))
	}
	if v.Name != "" {
		if out := cli.Send(fmt.Sprintf("vlan name %d %s", v.ID, v.Name), 3*time.Second); cliRejected(out) != nil {
			return fmt.Errorf("naming VLAN %d: %w", v.ID, cliRejected(out))
		}
	}
	cli.Send("exit", 2*time.Second)

	want := map[int]bool{}
	for _, p := range v.TaggedPorts {
		want[p] = true
	}
	cli.Send("configure", 3*time.Second)
	for _, p := range v.TaggedPorts {
		if out := cli.Send(fmt.Sprintf("interface 0/%d", p), 3*time.Second); cliRejected(out) != nil {
			return fmt.Errorf("selecting port 0/%d: %w", p, cliRejected(out))
		}
		for _, cmd := range []string{fmt.Sprintf("vlan participation include %d", v.ID), fmt.Sprintf("vlan tagging %d", v.ID)} {
			if out := cli.Send(cmd, 3*time.Second); cliRejected(out) != nil {
				return fmt.Errorf("port 0/%d %q: %w", p, cmd, cliRejected(out))
			}
		}
		cli.Send("exit", 2*time.Second)
	}
	for _, p := range previouslyTagged {
		if want[p] {
			continue
		}
		cli.Send(fmt.Sprintf("interface 0/%d", p), 3*time.Second)
		if out := cli.Send(fmt.Sprintf("vlan participation exclude %d", v.ID), 3*time.Second); cliRejected(out) != nil {
			return fmt.Errorf("removing port 0/%d from VLAN %d: %w", p, v.ID, cliRejected(out))
		}
		cli.Send("exit", 2*time.Second)
	}
	cli.Send("exit", 2*time.Second)
	return saveConfig(cli)
}

// DeleteVLAN removes the VLAN (and with it every membership) and saves.
func (c *Client) DeleteVLAN(id int) error {
	if id < 2 {
		return fmt.Errorf("refusing to delete VLAN %d", id)
	}
	cli, err := c.DialCLI()
	if err != nil {
		return err
	}
	defer cli.Close()
	cli.Send("vlan database", 3*time.Second)
	if out := cli.Send(fmt.Sprintf("no vlan %d", id), 4*time.Second); cliRejected(out) != nil {
		return fmt.Errorf("deleting VLAN %d: %w", id, cliRejected(out))
	}
	cli.Send("exit", 2*time.Second)
	return saveConfig(cli)
}
