package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &pr60xTimeResource{}
	_ resource.ResourceWithImportState = &pr60xTimeResource{}
)

type pr60xTimeResource struct {
	client *pr60x.Client
}

func NewPR60XTimeResource() resource.Resource { return &pr60xTimeResource{} }

type pr60xTimeModel struct {
	TimeZoneCode   types.Int64  `tfsdk:"timezone_code"`
	DaylightSaving types.Bool   `tfsdk:"daylight_saving"`
	CustomNTP      types.Bool   `tfsdk:"custom_ntp_servers"`
	NTPServers     types.List   `tfsdk:"ntp_servers"`
	LagEnabled     types.Bool   `tfsdk:"lag_enabled"`
	DualWANEnabled types.Bool   `tfsdk:"dual_wan_enabled"`
	DualWANMode    types.String `tfsdk:"dual_wan_mode"`
}

func (r *pr60xTimeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_time"
}

func (r *pr60xTimeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The PR60X's clock, plus two read-only \"this is off and should stay off\" " +
			"assertions.\n\n" +
			"**The router is the network's time authority.** The switches take SNTP from the LAN " +
			"and the AP has its own NTP client, so if this clock is wrong every device's logs are " +
			"wrong together — which is worse than one device being obviously wrong, because " +
			"nothing looks inconsistent.\n\n" +
			"**Timezone is an opaque index, and the devices disagree about the numbering.** The " +
			"router calls this timezone `16`; the WAX630E calls the same wall clock `260`. Neither " +
			"is an offset or an IANA name, and neither can be derived — read them off the devices " +
			"and import.\n\n" +
			"`lag_enabled` and `dual_wan_enabled` are read-only assertions rather than settings. " +
			"Both are off and both should be: every device here has a single uplink, and there is " +
			"one WAN. They are surfaced because a silently enabled dual-WAN failover tracking " +
			"public resolvers sends probe traffic continuously and can flap the default route — a " +
			"failure that looks like an ISP problem rather than a configuration one.",
		Attributes: map[string]schema.Attribute{
			"timezone_code": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "The router's own timezone index. Opaque — see the resource description. " +
					"Import rather than guess; a wrong value is accepted silently and just shifts the logs.",
			},
			"daylight_saving": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the router applies daylight saving for its timezone.",
			},
			"custom_ntp_servers": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "False uses the vendor pool in `ntp_servers`; true uses servers of your " +
					"own. **Ships false**, meaning the router — and therefore the whole network's idea " +
					"of time — depends on reaching NETGEAR's pool across the WAN.",
			},
			"ntp_servers": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Read-only. The NTP servers currently in use. Ships as " +
					"`time-b.netgear.com` and `time-c.netgear.com`. Changing these is a deliberate act " +
					"and is left to the web UI rather than made a one-line diff here.",
			},
			"lag_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Read-only. Link aggregation. Off, and correct — nothing here has two links to the same partner.",
			},
			"dual_wan_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Read-only. Second-WAN failover. Off, and correct — there is one WAN, the cable modem.",
			},
			"dual_wan_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Read-only. The failover mode that would apply if dual WAN were enabled.",
			},
		},
	}
}

func (r *pr60xTimeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.PR60X == nil {
		resp.Diagnostics.AddError("PR60X not configured",
			"This resource manages the router. Add a `pr60x` block to the provider, or set PR60X_PASSWORD.")
		return
	}
	r.client = c.PR60X
}

type pr60xTimeState struct {
	t   pr60x.TimeSettings
	ntp pr60x.NTPSettings
	lag pr60x.LagSettings
	wan pr60x.DualWANProfiles
}

func (r *pr60xTimeResource) read() (pr60xTimeState, error) {
	var s pr60xTimeState
	var err error
	if s.t, err = r.client.GetTimeSettings(); err != nil {
		return s, err
	}
	if s.ntp, err = r.client.GetNTPSettings(); err != nil {
		return s, err
	}
	if s.lag, err = r.client.GetLagSettings(); err != nil {
		return s, err
	}
	s.wan, err = r.client.GetDualWANProfiles()
	return s, err
}

func (m *pr60xTimeModel) fromWire(ctx context.Context, s pr60xTimeState, diags diagSink) {
	m.TimeZoneCode = types.Int64Value(int64(s.t.TimeZoneCode))
	m.DaylightSaving = i2b(s.t.DaylightSaving)
	m.CustomNTP = i2b(s.ntp.CustomServerEnable)
	list, d := types.ListValueFrom(ctx, types.StringType, s.ntp.ServerIPAddr)
	pump(d, diags)
	m.NTPServers = list
	m.LagEnabled = i2b(s.lag.Enabled)
	m.DualWANEnabled = i2b(s.wan.Enabled)
	m.DualWANMode = types.StringValue(s.wan.Mode)
}

// apply writes only the timezone, and only when it differs.
//
// NTP servers, LAG and dual WAN are read-only here on purpose. Each would need
// values this resource does not model to be turned on safely, and a resource
// that could half-enable dual-WAN failover would create exactly the flapping
// default route it is meant to warn about.
func (r *pr60xTimeResource) apply(ctx context.Context, plan *pr60xTimeModel, diags diagSink) {
	cur, err := r.read()
	if err != nil {
		diags.AddError("Could not read the router's time settings", err.Error())
		return
	}
	want := cur.t
	if v := plan.TimeZoneCode; !v.IsNull() && !v.IsUnknown() {
		want.TimeZoneCode = int(v.ValueInt64())
	}
	if v := plan.DaylightSaving; !v.IsNull() && !v.IsUnknown() {
		want.DaylightSaving = b2i(v)
	}
	if want != cur.t {
		if err := r.client.SetTimeSettings(want); err != nil {
			diags.AddError("Could not write the router's time settings", err.Error())
			return
		}
	}
	got, err := r.read()
	if err != nil {
		diags.AddError("Could not read back the router's time settings", err.Error())
		return
	}
	plan.fromWire(ctx, got, diags)
}

func (r *pr60xTimeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pr60xTimeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pr60xTimeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pr60xTimeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the router's time settings", err.Error())
		return
	}
	state.fromWire(ctx, got, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pr60xTimeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pr60xTimeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete DOES NOTHING TO THE DEVICE. Restoring a factory timezone would shift
// every future log line on the network's time authority as a side effect of a
// config cleanup.
func (r *pr60xTimeResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes any ID - the router has one clock:
//
//	terraform import netgear_pr60x_time.clock time
func (r *pr60xTimeResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the router's time settings", err.Error())
		return
	}
	var state pr60xTimeModel
	state.fromWire(ctx, got, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
