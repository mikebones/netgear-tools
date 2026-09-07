package wax630e

import (
	"errors"
	"fmt"
	"strings"
)

// --- radios -----------------------------------------------------------------

// RadioSettings is the per-radio PHY and airtime configuration.
//
// Everything is a STRING because the AP sends and expects strings even for
// numbers and booleans. Sending a JSON number is rejected with err_code 28,
// the same generic "Invalid configuration" the device gives for a misspelled
// key, so the failure does not tell you which of the two mistakes you made.
//
// THE RADIOS DO NOT SHARE A FIELD SET. wlan0 (2.4 GHz) accepts qamStatus,
// loadBalancingStatus and maxClientLoadBalancingStatus; wlan1 (5 GHz) does
// not, and asking for them there fails the WHOLE query rather than omitting
// them from the answer. That is why radioTemplate builds a different template
// per radio instead of sharing one.
type RadioSettings struct {
	RadioStatus        string `json:"radioStatus,omitempty"`
	OperateMode        string `json:"operateMode,omitempty"`
	Channel            string `json:"channel,omitempty"`
	ChannelWidth       string `json:"channelWidth,omitempty"`
	TxPower            string `json:"txPower,omitempty"`
	RTSThresholdStatus string `json:"rtsThresholdStatus,omitempty"`
	RTSThreshold       string `json:"rtsThreshold,omitempty"`
	FragLength         string `json:"fragLength,omitempty"`
	BeaconInterval     string `json:"beaconInterval,omitempty"`
	AMPDU              string `json:"ampdu,omitempty"`
	BeamForming        string `json:"beamForming,omitempty"`
	DTIMInterval       string `json:"dtimInterval,omitempty"`
	MaxWirelessClients string `json:"maxWirelessClients,omitempty"`
	FixedMulticastRate string `json:"fixedMulticastRate,omitempty"`
	RateLimitStatus    string `json:"rateLimitStatus,omitempty"`
	MaxRateLimit       string `json:"maxRateLimit,omitempty"`
	FrameBurst         string `json:"frameBurst,omitempty"`
	PreambleType       string `json:"preambleType,omitempty"`

	// 2.4 GHz only. See the note on the type.
	QAMStatus                    string `json:"qamStatus,omitempty"`
	LoadBalancingStatus          string `json:"loadBalancingStatus,omitempty"`
	MaxClientLoadBalancingStatus string `json:"maxClientLoadBalancingStatus,omitempty"`
}

// RadioNames are the radio keys this client models: wlan0 is 2.4 GHz and
// wlan1 is 5 GHz.
//
// wlan2 is the 6 GHz radio, and it is deliberately absent. It appears in the
// AP's own UI templates but does not answer the same field set, and this
// device has 6 GHz effectively unused - modelling it from a template that has
// never been exercised would put an untested guess in the drift baseline.
var RadioNames = []string{"wlan0", "wlan1"}

// radioTemplate is the query-by-example template for one radio: every field
// this client models, as empty strings, minus the ones that radio rejects.
func radioTemplate(radio string) map[string]any {
	t := map[string]any{
		"radioStatus": "", "operateMode": "", "channel": "", "channelWidth": "",
		"txPower": "", "rtsThresholdStatus": "", "rtsThreshold": "", "fragLength": "",
		"beaconInterval": "", "ampdu": "", "beamForming": "", "dtimInterval": "",
		"maxWirelessClients": "", "fixedMulticastRate": "", "rateLimitStatus": "",
		"maxRateLimit": "", "frameBurst": "", "preambleType": "",
	}
	if radio == "wlan0" {
		t["qamStatus"] = ""
		t["loadBalancingStatus"] = ""
		t["maxClientLoadBalancingStatus"] = ""
	}
	return t
}

type radioEnvelope struct {
	System struct {
		WlanSettings struct {
			WlanSettingTable map[string]RadioSettings `json:"wlanSettingTable"`
		} `json:"wlanSettings"`
	} `json:"system"`
}

// GetRadio returns one radio's settings. radio is "wlan0" or "wlan1".
func (c *Client) GetRadio(radio string) (RadioSettings, error) {
	var out radioEnvelope
	err := c.Call(map[string]any{"system": map[string]any{
		"wlanSettings": map[string]any{
			"wlanSettingTable": map[string]any{radio: radioTemplate(radio)},
		},
	}}, &out)
	if err != nil {
		return RadioSettings{}, err
	}
	r, ok := out.System.WlanSettings.WlanSettingTable[radio]
	if !ok {
		return RadioSettings{}, fmt.Errorf("the AP returned no settings for radio %q", radio)
	}
	return r, nil
}

// SetRadio writes one radio's settings.
//
// Read-modify-write: fetch with GetRadio, change what you mean to change, send
// the whole thing back. The omitempty tags exist for the per-radio field
// differences described on RadioSettings, NOT to invite partial writes.
//
// CHANGING radioStatus, channel, channelWidth OR operateMode BOUNCES THE
// RADIO - every client on it disassociates and re-associates. Seconds, not
// minutes, but it happens the instant the write lands.
func (c *Client) SetRadio(radio string, r RadioSettings) error {
	return c.Call(map[string]any{"system": map[string]any{
		"wlanSettings": map[string]any{
			"wlanSettingTable": map[string]any{radio: r},
		},
	}}, nil)
}

// --- SSID writes ------------------------------------------------------------

// SetSSIDDetails writes ONE SSID's configuration back to the AP.
//
// The write mirrors the read exactly. GetSSIDDetails returns
//
//	ssidGetDetails.<key>.band           e.g. "all"
//	ssidGetDetails.<key>.<radio>.<vap>  the ~41 settings
//
// and this sends the <radio>/<vap> half of that same tree back under
// ssidSetDetails, keyed by the same <key> ("SSID1", "SSID2", ...):
//
//	{"system":{"wlanSettings":{"wlanSettingTable":{"ssidSetDetails":{
//	    "SSID1": {"wlan0":{"vap0":{...}}, "wlan1":{"vap0":{...}}}}}}}}
//
// "band" is deliberately NOT sent back. It is a derived summary of which
// radios carry the SSID; the radio map is what actually decides that.
//
// PASS BACK WHAT YOU READ, MODIFIED. This takes a raw map rather than a struct
// for the same reason GetSSIDDetails returns one: the per-SSID field set is
// large and firmware-dependent, and a struct would silently drop the keys this
// firmware has and the struct does not. Dropping a key here means writing a
// default over a real setting - on a field like presharedKey or vlanID that is
// not a cosmetic loss.
//
// THIS BOUNCES THE SSID. Clients on it disassociate and reconnect. Writing
// values identical to the ones already there still bounces it, so there is no
// such thing as a free no-op apply.
func (c *Client) SetSSIDDetails(key string, radios map[string]any) error {
	if key == "" {
		return errors.New("an SSID key is required, for example \"SSID1\" - the keys " +
			"are whatever GetSSIDDetails returned")
	}
	if len(radios) == 0 {
		return fmt.Errorf("no radios given for %s: writing an empty radio map would take "+
			"the SSID off every band", key)
	}
	for radio, v := range radios {
		if !strings.HasPrefix(radio, "wlan") {
			return fmt.Errorf("%q is not a radio key; expected wlan0, wlan1 or wlan2", radio)
		}
		vaps, ok := v.(map[string]any)
		if !ok || len(vaps) == 0 {
			return fmt.Errorf("radio %s must map a vap key to its settings, the shape "+
				"GetSSIDDetails returns", radio)
		}
	}
	return c.Call(map[string]any{"system": map[string]any{
		"wlanSettings": map[string]any{
			"wlanSettingTable": map[string]any{
				"ssidSetDetails": map[string]any{key: radios},
			},
		},
	}}, nil)
}
