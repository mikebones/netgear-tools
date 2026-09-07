package provider

import (
	"context"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/wax630e"
)

var (
	_ resource.Resource                = &wax630eTimeResource{}
	_ resource.ResourceWithImportState = &wax630eTimeResource{}
)

type wax630eTimeResource struct {
	client *wax630e.Client
}

func NewWAX630ETimeResource() resource.Resource { return &wax630eTimeResource{} }

type wax630eTimeModel struct {
	TimeZone       types.String `tfsdk:"timezone_index"`
	DaylightSaving types.Bool   `tfsdk:"daylight_saving"`
	NTPEnabled     types.Bool   `tfsdk:"ntp_enabled"`
	CustomNTP      types.Bool   `tfsdk:"custom_ntp_server"`
	NTPAddress     types.String `tfsdk:"ntp_address"`
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func (r *wax630eTimeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_time"
}

func (r *wax630eTimeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The WAX630E's clock and NTP client.\n\n" +
			"**The clock is a debugging trap, not a cosmetic setting.** Every syslog line this AP " +
			"ships to the cluster's receiver is stamped with it. An AP whose timezone has silently " +
			"reverted does not look broken - it looks like the logs are lying, which costs far more " +
			"time than an outage would.\n\n" +
			"**This is a real deviation from factory.** The firmware's `/etc/default-config` ships " +
			"`timeZone 93`; this AP runs `260`. A factory reset therefore moves the clock, and " +
			"nothing about the AP's behaviour makes that obvious.\n\n" +
			"Applying this does not interrupt anything - no radio bounce, no client disconnects.",
		Attributes: map[string]schema.Attribute{
			"timezone_index": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "The AP's own timezone index. **Not an offset and not an IANA name** - " +
					"it is an opaque position in a table the firmware does not expose, so it cannot be " +
					"derived and must be read from the device. `93` is the factory value; this AP runs " +
					"`260`. Import before setting it: a wrong index is accepted silently and just " +
					"shifts every timestamp.",
			},
			"daylight_saving": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the AP applies daylight saving for its timezone.",
			},
			"ntp_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "Whether the AP syncs its clock at all. Leave on - the alternative is a " +
					"clock that drifts and takes the syslog timestamps with it.",
			},
			"custom_ntp_server": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "False uses the vendor pool named in `ntp_address`; true uses a server of " +
					"your own. **The factory value is false with `time-b.netgear.com`**, meaning a " +
					"reset AP reaches out to NETGEAR for time rather than to anything on this network.",
			},
			"ntp_address": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "The NTP server. Ships as `time-b.netgear.com`. Pointing this at the LAN " +
					"gateway instead keeps the AP's clock consistent with the switches, which already " +
					"take SNTP locally - and means the AP still gets time when the WAN is down, which " +
					"is exactly when the logs matter.",
			},
		},
	}
}

func (r *wax630eTimeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m *wax630eTimeModel) fromWire(t wax630e.TimeSettings) {
	m.TimeZone = types.StringValue(t.TimeZone)
	m.DaylightSaving = wireBool(t.DaylightSaving)
	m.NTPEnabled = wireBool(t.NTPClientStatus)
	m.CustomNTP = wireBool(t.CustomNTPServer)
	m.NTPAddress = types.StringValue(t.NTPAddr)
}

func (r *wax630eTimeResource) apply(plan *wax630eTimeModel, diags diagSink) {
	cur, err := r.client.GetTime()
	if err != nil {
		diags.AddError("Could not read the time settings", err.Error())
		return
	}
	want := cur
	if v := plan.TimeZone; !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		want.TimeZone = v.ValueString()
	}
	want.DaylightSaving = boolWire(plan.DaylightSaving)
	want.NTPClientStatus = boolWire(plan.NTPEnabled)
	want.CustomNTPServer = boolWire(plan.CustomNTP)
	if v := plan.NTPAddress; !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		want.NTPAddr = v.ValueString()
	}
	if err := r.client.SetTime(want); err != nil {
		diags.AddError("Could not write the time settings", err.Error())
		return
	}
	got, err := r.client.GetTime()
	if err != nil {
		diags.AddError("Could not read back the time settings", err.Error())
		return
	}
	plan.fromWire(got)
}

func (r *wax630eTimeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan wax630eTimeModel
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

func (r *wax630eTimeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state wax630eTimeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetTime()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the time settings", err.Error())
		return
	}
	state.fromWire(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *wax630eTimeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan wax630eTimeModel
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

// Delete DOES NOTHING TO THE DEVICE, deliberately. Restoring the factory clock
// would move every future syslog timestamp as a side effect of a config
// cleanup, and the factory NTP server is the vendor's rather than anything on
// this network.
func (r *wax630eTimeResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes any ID - there is one clock:
//
//	terraform import netgear_wax630e_time.clock time
func (r *wax630eTimeResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetTime()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the time settings", err.Error())
		return
	}
	var state wax630eTimeModel
	state.fromWire(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
