package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/wax630e"
)

var (
	_ resource.Resource                = &wax630eRadioResource{}
	_ resource.ResourceWithImportState = &wax630eRadioResource{}
)

type wax630eRadioResource struct {
	client *wax630e.Client
}

func NewWAX630ERadioResource() resource.Resource { return &wax630eRadioResource{} }

type wax630eRadioModel struct {
	Radio              types.String `tfsdk:"radio"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	OperateMode        types.String `tfsdk:"operate_mode"`
	Channel            types.String `tfsdk:"channel"`
	ChannelWidth       types.String `tfsdk:"channel_width"`
	TxPower            types.String `tfsdk:"tx_power"`
	BeaconInterval     types.String `tfsdk:"beacon_interval"`
	DTIMInterval       types.String `tfsdk:"dtim_interval"`
	RTSThreshold       types.String `tfsdk:"rts_threshold"`
	FragLength         types.String `tfsdk:"fragmentation_length"`
	MaxWirelessClients types.String `tfsdk:"max_wireless_clients"`
	RateLimitEnabled   types.Bool   `tfsdk:"rate_limit_enabled"`
	MaxRateLimit       types.String `tfsdk:"max_rate_limit_mbps"`
	AMPDU              types.Bool   `tfsdk:"ampdu"`
	BeamForming        types.Bool   `tfsdk:"beamforming"`
	FrameBurst         types.Bool   `tfsdk:"frame_burst"`
	QAMStatus          types.Bool   `tfsdk:"qam256"`
}

func (r *wax630eRadioResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_radio"
}

func (r *wax630eRadioResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "PHY and airtime settings for one radio on the WAX630E.\n\n" +
			"**This exists to survive a factory reset and to notice a firmware upgrade quietly " +
			"changing something.** Almost every value here is already what it should be; declaring " +
			"them means a `plan` says so, rather than nobody finding out until the wifi is subtly " +
			"worse. This AP's upgrade flow offers to factory-reset the device as part of a version " +
			"jump, and that is not a hypothetical - it was offered twice during the 10.8.x to " +
			"12.8.0.6 climb.\n\n" +
			"**Values are strings, including the numeric ones.** The device sends and expects " +
			"strings throughout, and a JSON number is rejected with the same generic " +
			"`err_code 28: Invalid configuration` it gives for a misspelled key - so a type mistake " +
			"and a typo are indistinguishable from the error. They are passed through as strings " +
			"rather than prettied up into Terraform numbers and bools everywhere, because the " +
			"mapping is not always obvious and an invented one would be a second thing to get " +
			"wrong.\n\n" +
			"**The two radios do NOT accept the same fields.** `qam256` exists on `wlan0` only. " +
			"Setting it on `wlan1` fails the whole write, so the resource rejects that in plan " +
			"rather than sending something the AP will refuse.\n\n" +
			"**Changing `enabled`, `channel`, `channel_width` or `operate_mode` BOUNCES THE RADIO** " +
			"- every client on it disassociates and reconnects. Seconds, but real, and it happens " +
			"the instant apply lands.",
		Attributes: map[string]schema.Attribute{
			"radio": schema.StringAttribute{
				Required: true,
				Description: "Radio key as the device names it: `wlan0` is 2.4 GHz, `wlan1` is 5 GHz. " +
					"`wlan2` (6 GHz) is not supported here - it appears in the AP's own UI templates but " +
					"does not answer the same field set, and shipping an untested template would put a " +
					"guess into the drift baseline.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the radio transmits. **False takes the band off the air.**",
			},
			"operate_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "802.11 mode, as the device's own numeric code. `9` on 2.4 GHz and `10` on " +
					"5 GHz are what this AP ships. The codes are not documented anywhere the device " +
					"exposes; read the current value rather than guessing one.",
			},
			"channel": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Channel number, or `0` for automatic. Leave at `0` unless you are working " +
					"around a specific interferer - the AP re-picks on boot and after radar events, and a " +
					"pinned channel cannot do either.",
			},
			"channel_width": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Channel width code, `0` being the device's automatic choice. Wider is not " +
					"better on 2.4 GHz, where there is not room for it.",
			},
			"tx_power": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Transmit power code, `0` being maximum. Turning power DOWN is a real " +
					"technique for a dense deployment - it stops distant clients clinging to a weak " +
					"association - but with one AP it only shrinks coverage.",
			},
			"beacon_interval": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Beacon interval in TU. `100` is standard and there is rarely a reason to move it.",
			},
			"dtim_interval": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "DTIM period. Higher lets power-saving clients sleep longer at the cost of " +
					"multicast latency; `2` is this AP's default and a reasonable middle.",
			},
			"rts_threshold": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "RTS/CTS threshold in bytes. `2346` disables it in practice, which is the " +
					"default and correct without hidden nodes.",
			},
			"fragmentation_length": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Fragmentation threshold in bytes. `2346` disables it. Fragmentation is a " +
					"legacy remedy and costs throughput.",
			},
			"max_wireless_clients": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Association limit for this radio. Ships at `128` on 2.4 GHz and `200` on 5 GHz.",
			},
			"rate_limit_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Whether the per-radio rate limit applies. **This AP ships with it ON at " +
					"50 Mbps on both radios**, which is a real cap that somebody will eventually spend an " +
					"afternoon not finding. Declaring it is how it stops being a surprise.",
			},
			"max_rate_limit_mbps": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The rate limit itself, in Mbps, applied when `rate_limit_enabled` is true.",
			},
			"ampdu": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "A-MPDU frame aggregation. On by default and should stay on; it is most of " +
					"why 802.11n and later reach their headline rates.",
			},
			"beamforming": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Explicit transmit beamforming. On by default.",
			},
			"frame_burst": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Frame bursting. Off by default. It favours a single fast client at the cost " +
					"of fairness, so it is the wrong trade with several clients sharing the band.",
			},
			"qam256": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "256-QAM on 2.4 GHz. **`wlan0` only** - setting it on `wlan1` fails the " +
					"whole write, so this resource refuses it at plan time instead.",
			},
		},
	}
}

func (r *wax630eRadioResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.WAX630E == nil {
		resp.Diagnostics.AddError("WAX630E not configured",
			"This resource manages the access point. Add a `wax630e` block to the provider, or set WAX630E_PASSWORD.")
		return
	}
	r.client = c.WAX630E
}

// wireBool maps the device's "1"/"0" strings to a Terraform bool. Anything
// else reads as false, which is the safe direction for every flag here.
func wireBool(s string) types.Bool { return types.BoolValue(strings.TrimSpace(s) == "1") }

func boolWire(b types.Bool) string {
	if b.ValueBool() {
		return "1"
	}
	return "0"
}

func (m *wax630eRadioModel) fromWire(radio string, s wax630e.RadioSettings) {
	m.Radio = types.StringValue(radio)
	m.Enabled = wireBool(s.RadioStatus)
	m.OperateMode = types.StringValue(s.OperateMode)
	m.Channel = types.StringValue(s.Channel)
	m.ChannelWidth = types.StringValue(s.ChannelWidth)
	m.TxPower = types.StringValue(s.TxPower)
	m.BeaconInterval = types.StringValue(s.BeaconInterval)
	m.DTIMInterval = types.StringValue(s.DTIMInterval)
	m.RTSThreshold = types.StringValue(s.RTSThreshold)
	m.FragLength = types.StringValue(s.FragLength)
	m.MaxWirelessClients = types.StringValue(s.MaxWirelessClients)
	m.RateLimitEnabled = wireBool(s.RateLimitStatus)
	m.MaxRateLimit = types.StringValue(s.MaxRateLimit)
	m.AMPDU = wireBool(s.AMPDU)
	m.BeamForming = wireBool(s.BeamForming)
	m.FrameBurst = wireBool(s.FrameBurst)
	// wlan1 does not carry this field at all; report false rather than leaving
	// it null, so the value is comparable across both radios.
	m.QAMStatus = wireBool(s.QAMStatus)
}

// apply read-modify-writes the radio. The read first is not politeness: the
// AP's field set differs per radio and per firmware, and starting from the
// live row means a field this provider does not model cannot be cleared by
// writing a zero value over it.
func (r *wax630eRadioResource) apply(plan *wax630eRadioModel, diags diagSink) {
	radio := plan.Radio.ValueString()
	if radio != "wlan0" && radio != "wlan1" {
		diags.AddError("Unsupported radio",
			fmt.Sprintf("radio must be wlan0 (2.4 GHz) or wlan1 (5 GHz). Got %q. "+
				"wlan2 is the 6 GHz radio and does not answer the same field set.", radio))
		return
	}
	if radio != "wlan0" && plan.QAMStatus.ValueBool() {
		diags.AddError("qam256 is 2.4 GHz only",
			"The AP accepts qamStatus on wlan0 only. Setting it on "+radio+" makes the device "+
				"reject the entire write with err_code 28, so it is refused here instead.")
		return
	}

	cur, err := r.client.GetRadio(radio)
	if err != nil {
		diags.AddError("Could not read the radio", err.Error())
		return
	}

	want := cur
	want.RadioStatus = boolWire(plan.Enabled)
	want.OperateMode = plan.OperateMode.ValueString()
	want.Channel = plan.Channel.ValueString()
	want.ChannelWidth = plan.ChannelWidth.ValueString()
	want.TxPower = plan.TxPower.ValueString()
	want.BeaconInterval = plan.BeaconInterval.ValueString()
	want.DTIMInterval = plan.DTIMInterval.ValueString()
	want.RTSThreshold = plan.RTSThreshold.ValueString()
	want.FragLength = plan.FragLength.ValueString()
	want.MaxWirelessClients = plan.MaxWirelessClients.ValueString()
	want.RateLimitStatus = boolWire(plan.RateLimitEnabled)
	want.MaxRateLimit = plan.MaxRateLimit.ValueString()
	want.AMPDU = boolWire(plan.AMPDU)
	want.BeamForming = boolWire(plan.BeamForming)
	want.FrameBurst = boolWire(plan.FrameBurst)
	if radio == "wlan0" {
		want.QAMStatus = boolWire(plan.QAMStatus)
	}

	if err := r.client.SetRadio(radio, want); err != nil {
		diags.AddError("Could not write the radio settings", err.Error())
		return
	}
	got, err := r.client.GetRadio(radio)
	if err != nil {
		diags.AddError("Could not read back the radio settings", err.Error())
		return
	}
	plan.fromWire(radio, got)
}

func (r *wax630eRadioResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan wax630eRadioModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *wax630eRadioResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state wax630eRadioModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetRadio(state.Radio.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read the radio settings", err.Error())
		return
	}
	state.fromWire(state.Radio.ValueString(), got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *wax630eRadioResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan wax630eRadioModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete DOES NOTHING TO THE DEVICE, deliberately.
//
// There is no "unconfigured radio" to return to. The tidy-looking inverse -
// restoring shipped defaults - would bounce a live radio and drop every
// wireless client as a side effect of a config cleanup, and the shipped
// default for this AP includes a 50 Mbps rate limit nobody would want
// reinstated silently. Removing the resource stops Terraform tracking the
// radio; the radio keeps running exactly as it is.
func (r *wax630eRadioResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes the radio key:
//
//	terraform import netgear_wax630e_radio.two_ghz wlan0
func (r *wax630eRadioResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	radio := strings.TrimSpace(req.ID)
	if radio != "wlan0" && radio != "wlan1" {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import this resource with the radio key, for example "+
				"`terraform import netgear_wax630e_radio.two_ghz wlan0`. Valid keys are wlan0 and wlan1. Got: "+req.ID)
		return
	}
	got, err := r.client.GetRadio(radio)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the radio settings", err.Error())
		return
	}
	var state wax630eRadioModel
	state.fromWire(radio, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("radio"), radio)...)
}
