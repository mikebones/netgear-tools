package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510SNTPResource{}
	_ resource.ResourceWithImportState = &ms510SNTPResource{}
)

type ms510SNTPResource struct {
	client *ms510txup.Client
}

func NewMS510SNTPResource() resource.Resource { return &ms510SNTPResource{} }

type ms510SNTPServerModel struct {
	Address  types.String `tfsdk:"address"`
	Port     types.Int64  `tfsdk:"port"`
	Priority types.Int64  `tfsdk:"priority"`
	Version  types.Int64  `tfsdk:"version"`
}

type ms510SNTPModel struct {
	TimezoneName    types.String           `tfsdk:"timezone_name"`
	OffsetHours     types.Int64            `tfsdk:"utc_offset_hours"`
	OffsetMinutes   types.Int64            `tfsdk:"utc_offset_minutes"`
	Servers         []ms510SNTPServerModel `tfsdk:"servers"`
	LastSyncSuccess types.Bool             `tfsdk:"last_sync_success"`
}

func (r *ms510SNTPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_sntp"
}

func (r *ms510SNTPResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Clock source and time servers on the MS510TXUP.\n\n" +
			"This switch has no battery-backed RTC. It boots reading December 2022 every time, so SNTP is the " +
			"only thing standing between you and three-year-old timestamps on everything it logs.\n\n" +
			"The resource always configures **unicast** SNTP. That is not a preference - the firmware's " +
			"`sntpMode` is `[0 Unicast, 1 Broadcast]`, the opposite of the obvious guess, and in broadcast mode " +
			"the client waits for NTP broadcasts and never sends a request. The failure is completely silent: " +
			"the CLI reports `SNTP is Enabled` with a server configured, no error is raised anywhere, and the " +
			"request counter simply stays at zero forever.\n\n" +
			"Destroying this resource returns the clock to local (manually set) time, which on a switch with no " +
			"RTC means it will be wrong again after the next reboot.",
		Attributes: map[string]schema.Attribute{
			"timezone_name": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:     stringdefault.StaticString("UTC"),
				Description: "Timezone label, e.g. \"MST\". Cosmetic on the device but it appears in log timestamps.",
			},
			"utc_offset_hours": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(0),
				Description: "Hours offset from UTC, -12 to 13.",
			},
			"utc_offset_minutes": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(0),
				Description: "Additional minutes offset from UTC, 0 to 59.",
			},
			"last_sync_success": schema.BoolAttribute{
				Computed: true,
				Description: "Whether the switch's most recent SNTP attempt succeeded. Read-only, and worth " +
					"looking at after an apply: a configuration that is accepted but never syncs is this " +
					"device's characteristic failure.",
			},
			"servers": schema.ListNestedAttribute{
				Required:    true,
				Description: "Time sources, at most three. The switch will not reach a server it cannot route to.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"address": schema.StringAttribute{
							Required:    true,
							Description: "Server address. Prefer a literal IP - the switch's own DNS is a separate setting.",
						},
						"port": schema.Int64Attribute{
							Optional: true, Computed: true,
							Default:     int64default.StaticInt64(123),
							Description: "Server port.",
						},
						"priority": schema.Int64Attribute{
							Optional: true, Computed: true,
							Default:     int64default.StaticInt64(1),
							Description: "Priority, 1 to 3. Also the key the firmware uses to delete a row.",
						},
						"version": schema.Int64Attribute{
							Optional: true, Computed: true,
							Default:     int64default.StaticInt64(4),
							Description: "NTP version, 1 to 4.",
						},
					},
				},
			},
		},
	}
}

func (r *ms510SNTPResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.MS510TXUP == nil {
		resp.Diagnostics.AddError("MS510TXUP not configured",
			"This resource manages the MS510TXUP. Add an `ms510txup` block to the provider, or set MS510TXUP_PASSWORD.")
		return
	}
	r.client = c.MS510TXUP
}

// apply writes the clock configuration and reconciles the server list, then
// reads everything back. The read-back is not optional on this firmware: it
// answers save_success for field sets it silently discarded.
func (r *ms510SNTPResource) apply(plan *ms510SNTPModel, diags interface {
	AddError(string, string)
}) {
	if err := r.client.SetSNTP(plan.TimezoneName.ValueString(),
		int(plan.OffsetHours.ValueInt64()), int(plan.OffsetMinutes.ValueInt64())); err != nil {
		diags.AddError("Could not set the clock source", err.Error())
		return
	}

	existing, err := r.client.ListSNTPServers()
	if err != nil {
		diags.AddError("Could not list time servers", err.Error())
		return
	}

	wanted := map[string]ms510SNTPServerModel{}
	for _, s := range plan.Servers {
		wanted[s.Address.ValueString()] = s
	}
	// Remove anything not in the plan. The delete key is the row's priority,
	// not its address - the UI posts the selected row's `pri`.
	for _, e := range existing {
		if _, keep := wanted[e.IP]; !keep {
			if err := r.client.DeleteSNTPServer(e.Pri); err != nil {
				diags.AddError("Could not remove a time server", err.Error())
				return
			}
		}
	}
	have := map[string]bool{}
	for _, e := range existing {
		if _, keep := wanted[e.IP]; keep {
			have[e.IP] = true
		}
	}
	for _, s := range plan.Servers {
		if have[s.Address.ValueString()] {
			continue
		}
		// The field is `ip`. Sending `addr` is accepted, reported as saved,
		// and discards the entire entry.
		if err := r.client.AddSNTPServer(ms510txup.SNTPServer{
			Type: 0,
			IP:   s.Address.ValueString(),
			Port: int(s.Port.ValueInt64()),
			Pri:  int(s.Priority.ValueInt64()),
			Ver:  int(s.Version.ValueInt64()),
		}); err != nil {
			diags.AddError("Could not add a time server", err.Error())
			return
		}
	}

	if !r.readInto(plan, diags) {
		return
	}
}

func (r *ms510SNTPResource) readInto(m *ms510SNTPModel, diags interface {
	AddError(string, string)
}) bool {
	t, err := r.client.GetTime()
	if err != nil {
		diags.AddError("Could not read the clock configuration", err.Error())
		return false
	}
	if t.Type != ms510txup.ClockSNTP {
		diags.AddError("The switch did not accept SNTP as the clock source",
			fmt.Sprintf("Read back type=%d, wanted %d. This firmware reports save_success for writes it "+
				"discards, so a partial or misnamed field set looks exactly like success.",
				t.Type, ms510txup.ClockSNTP))
		return false
	}

	m.TimezoneName = types.StringValue(t.TzName)
	m.OffsetHours = types.Int64Value(int64(t.TzDiff / 60))
	// TzDiff is signed minutes east of UTC; the minutes part carries its sign.
	mins := t.TzDiff % 60
	if mins < 0 {
		mins = -mins
	}
	m.OffsetMinutes = types.Int64Value(int64(mins))

	servers, err := r.client.ListSNTPServers()
	if err != nil {
		diags.AddError("Could not read time servers", err.Error())
		return false
	}
	m.Servers = nil
	for _, s := range servers {
		m.Servers = append(m.Servers, ms510SNTPServerModel{
			Address:  types.StringValue(s.IP),
			Port:     types.Int64Value(int64(s.Port)),
			Priority: types.Int64Value(int64(s.Pri)),
			Version:  types.Int64Value(int64(s.Ver)),
		})
	}

	ok, err := r.client.SNTPLastSyncOK()
	if err != nil {
		diags.AddError("Could not read SNTP status", err.Error())
		return false
	}
	m.LastSyncSuccess = types.BoolValue(ok)
	return true
}

func (r *ms510SNTPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510SNTPModel
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

func (r *ms510SNTPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510SNTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readInto(&state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510SNTPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510SNTPModel
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

func (r *ms510SNTPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510SNTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetLocalClock(state.TimezoneName.ValueString(),
		int(state.OffsetHours.ValueInt64()), int(state.OffsetMinutes.ValueInt64())); err != nil {
		resp.Diagnostics.AddError("Could not return the clock to local time", err.Error())
	}
	// Server entries are left in place: they are harmless with the clock
	// source set to local, and keeping them makes re-enabling a one-liner.
}

func (r *ms510SNTPResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var state ms510SNTPModel
	if !r.readInto(&state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
