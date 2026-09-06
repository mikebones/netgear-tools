package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

// IGMP snooping on the MS510TXUP is TWO switches, not one, and that is the
// entire reason this file has two resources.
//
// mcast_igsGlobal is the master enable. Turning it on changes nothing on its
// own: every VLAN keeps its own admin-mode row, and a VLAN sitting at 0 still
// floods multicast to every port exactly as before. The switch was found with
// the global flag ON and all six VLAN rows OFF - which reads as "snooping is
// configured" on the summary page while the switch is doing no snooping at
// all. Modelling only the global flag would reproduce that trap in Terraform.
//
// So: netgear_ms510txup_igmp_snooping is the master, and one
// netgear_ms510txup_igmp_snooping_vlan per VLAN that should actually snoop.

var (
	_ resource.Resource                = &ms510IGMPSnoopingResource{}
	_ resource.ResourceWithImportState = &ms510IGMPSnoopingResource{}

	_ resource.Resource                = &ms510IGMPSnoopingVLANResource{}
	_ resource.ResourceWithImportState = &ms510IGMPSnoopingVLANResource{}
)

// --- global ------------------------------------------------------------------

type ms510IGMPSnoopingResource struct {
	client *ms510txup.Client
}

func NewMS510IGMPSnoopingResource() resource.Resource { return &ms510IGMPSnoopingResource{} }

type ms510IGMPSnoopingModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (r *ms510IGMPSnoopingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_igmp_snooping"
}

func (r *ms510IGMPSnoopingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The MS510TXUP's master IGMP snooping enable.\n\n" +
			"**On its own this does nothing.** It is a gate, not a behaviour: with it on and a VLAN's own " +
			"admin mode off, that VLAN still floods every multicast frame to every port. Pair it with a " +
			"`netgear_ms510txup_igmp_snooping_vlan` for each VLAN that should snoop, or the switch will " +
			"report snooping as enabled while snooping nothing.\n\n" +
			"This matters more on this switch than anywhere else on the network: all five cluster nodes hang " +
			"off it - the four Pis on ports 1-4 and hme-srv-01 on port 10 - on a LAN carrying mDNS, SSDP and " +
			"Plex GDM discovery. Flooded multicast is a standing tax on NICs that were already dropping " +
			"frames on an undersized RX ring.\n\n" +
			"A settings singleton: destroying the resource turns snooping off rather than deleting anything.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Master enable (igsState on the wire).",
			},
		},
	}
}

func (r *ms510IGMPSnoopingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "IGMP snooping"); c != nil {
		r.client = c
	}
}

func (r *ms510IGMPSnoopingResource) apply(plan *ms510IGMPSnoopingModel, diags diagSink) {
	if err := r.client.SetIGMPSnooping(plan.Enabled.ValueBool()); err != nil {
		diags.AddError("Could not set IGMP snooping", err.Error())
		return
	}
	// Read back. This firmware answers save_success for writes it discarded,
	// so the reply is not evidence of anything.
	got, err := r.client.GetIGMPSnooping()
	if err != nil {
		diags.AddError("Could not read back IGMP snooping", err.Error())
		return
	}
	plan.Enabled = types.BoolValue(got.State == 1)
}

func (r *ms510IGMPSnoopingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510IGMPSnoopingModel
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

func (r *ms510IGMPSnoopingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510IGMPSnoopingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetIGMPSnooping()
	if err != nil {
		resp.Diagnostics.AddError("Could not read IGMP snooping", err.Error())
		return
	}
	state.Enabled = types.BoolValue(got.State == 1)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510IGMPSnoopingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510IGMPSnoopingModel
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

func (r *ms510IGMPSnoopingResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.SetIGMPSnooping(false); err != nil {
		resp.Diagnostics.AddError("Could not disable IGMP snooping", err.Error())
	}
}

func (r *ms510IGMPSnoopingResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetIGMPSnooping()
	if err != nil {
		resp.Diagnostics.AddError("Could not read IGMP snooping", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx,
		&ms510IGMPSnoopingModel{Enabled: types.BoolValue(got.State == 1)})...)
}

// --- per VLAN ----------------------------------------------------------------

type ms510IGMPSnoopingVLANResource struct {
	client *ms510txup.Client
}

func NewMS510IGMPSnoopingVLANResource() resource.Resource { return &ms510IGMPSnoopingVLANResource{} }

type ms510IGMPSnoopingVLANModel struct {
	VLANID            types.Int64 `tfsdk:"vlan_id"`
	Enabled           types.Bool  `tfsdk:"enabled"`
	FastLeave         types.Bool  `tfsdk:"fast_leave"`
	HostTimeout       types.Int64 `tfsdk:"host_timeout"`
	MaxResponseTime   types.Int64 `tfsdk:"max_response_time"`
	MRouterTimeout    types.Int64 `tfsdk:"mrouter_timeout"`
	ReportSuppression types.Bool  `tfsdk:"report_suppression"`
	QuerierEnabled    types.Bool  `tfsdk:"querier_enabled"`
	QueryInterval     types.Int64 `tfsdk:"query_interval"`
}

func (r *ms510IGMPSnoopingVLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_igmp_snooping_vlan"
}

func (r *ms510IGMPSnoopingVLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "IGMP snooping settings for one VLAN on the MS510TXUP.\n\n" +
			"**This is the row that decides whether snooping happens.** " +
			"`netgear_ms510txup_igmp_snooping` is only the master gate; a VLAN whose row is disabled floods " +
			"multicast to every port regardless of it.\n\n" +
			"**Creates nothing.** Every VLAN that exists on the switch already has a row here - the VLAN " +
			"table creates and destroys them, not this resource. Create only edits the existing row, and " +
			"Delete returns it to disabled with the shipped timers rather than removing anything. Applying " +
			"this for a VLAN the switch does not have fails at read-back with a clear error rather than " +
			"silently doing nothing.\n\n" +
			"The timers default to the switch's own shipped values, so a config that only sets `enabled` " +
			"leaves them where they were.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required: true,
				Description: "VLAN whose snooping row this manages. The VLAN must already exist on the " +
					"switch - see netgear_ms510txup_vlan.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Admin mode for this VLAN (state on the wire).",
			},
			"fast_leave": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Drop a port from a group the moment it sends a leave, without the usual " +
					"group-specific query. Safe only where each port has one host behind it; on a port " +
					"feeding another switch it cuts off the receivers that did not leave.",
			},
			"host_timeout": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(260),
				Description: "Seconds without a report before a host is aged out of a group. Switch default 260.",
			},
			"max_response_time": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(10),
				Description: "Seconds a host may wait before answering a query - it staggers the replies. " +
					"Must stay below host_timeout. Switch default 10.",
			},
			"mrouter_timeout": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				Description: "Seconds before a learned multicast-router port is aged out. Switch default 0, " +
					"which on this firmware means the built-in default rather than 'immediately'.",
			},
			"report_suppression": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Forward only one membership report per group upstream instead of every host's. " +
					"Quieter, but it hides per-host membership from anything upstream that wants it.",
			},
			"querier_enabled": schema.BoolAttribute{
				Computed: true,
				Description: "READ-ONLY HERE, and deliberately so. This reports the row's qryEn field, " +
					"which is THE SAME UNDERLYING SETTING as `netgear_ms510txup_igmp_querier_vlan` - the " +
					"switch exposes one flag through two endpoints (mcast_igsVlan's qryEn and " +
					"mcast_igsQryVlan's VLAN list). " +
					"Making it writable here as well produced two resources fighting over one field: every " +
					"plan showed a diff and every apply flipped it back. Manage the querier with " +
					"`netgear_ms510txup_igmp_querier_vlan`, which speaks the endpoint that actually works, " +
					"and read it here.",
			},
			"query_interval": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(60),
				Description: "Seconds between queries when querier_enabled is true. 1-1800. Switch default 60.",
			},
		},
	}
}

func (r *ms510IGMPSnoopingVLANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "per-VLAN IGMP snooping"); c != nil {
		r.client = c
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (m *ms510IGMPSnoopingVLANModel) toWire() ms510txup.IGMPSnoopingVLAN {
	return ms510txup.IGMPSnoopingVLAN{
		VLANID:       int(m.VLANID.ValueInt64()),
		State:        boolToInt(m.Enabled.ValueBool()),
		FastLeave:    boolToInt(m.FastLeave.ValueBool()),
		HostTimeout:  int(m.HostTimeout.ValueInt64()),
		MaxResponse:  int(m.MaxResponseTime.ValueInt64()),
		MRouterTime:  int(m.MRouterTimeout.ValueInt64()),
		ReportSuppEn: boolToInt(m.ReportSuppression.ValueBool()),
		// QuerierEn is filled in by apply() from the LIVE row, never from the
		// plan - see the querier_enabled schema note. Writing a planned value
		// here would let this resource silently disable the querier that
		// netgear_ms510txup_igmp_querier_vlan owns.
		QueryIntvl: int(m.QueryInterval.ValueInt64()),
	}
}

func (m *ms510IGMPSnoopingVLANModel) fromWire(w ms510txup.IGMPSnoopingVLAN) {
	m.VLANID = types.Int64Value(int64(w.VLANID))
	m.Enabled = types.BoolValue(w.State == 1)
	m.FastLeave = types.BoolValue(w.FastLeave == 1)
	m.HostTimeout = types.Int64Value(int64(w.HostTimeout))
	m.MaxResponseTime = types.Int64Value(int64(w.MaxResponse))
	m.MRouterTimeout = types.Int64Value(int64(w.MRouterTime))
	m.ReportSuppression = types.BoolValue(w.ReportSuppEn == 1)
	m.QuerierEnabled = types.BoolValue(w.QuerierEn == 1)
	m.QueryInterval = types.Int64Value(int64(w.QueryIntvl))
}

// apply writes the row and reads it straight back.
//
// The read-back is load-bearing twice over. This firmware answers
// save_success for writes it silently discarded - that is how the missing
// selEntry field went unnoticed for so long - and a vlan_id the switch does
// not have simply has no row, which without this check would look like a
// successful apply.
func (r *ms510IGMPSnoopingVLANResource) apply(plan *ms510IGMPSnoopingVLANModel, diags diagSink) {
	want := plan.toWire()
	// Carry the querier flag forward from the device. It is owned by
	// netgear_ms510txup_igmp_querier_vlan; this row merely has to not clobber
	// it, because the write sends the whole row.
	if cur, err := r.client.GetIGMPSnoopingVLAN(want.VLANID); err == nil && cur != nil {
		want.QuerierEn = cur.QuerierEn
	}
	if err := r.client.SetIGMPSnoopingVLAN(want, want.State == 1); err != nil {
		diags.AddError("Could not set IGMP snooping for the VLAN", err.Error())
		return
	}
	got, err := r.client.GetIGMPSnoopingVLAN(want.VLANID)
	if err != nil {
		diags.AddError("Could not read back IGMP snooping for the VLAN", err.Error())
		return
	}
	if got == nil {
		diags.AddError("The switch has no row for that VLAN",
			fmt.Sprintf("VLAN %d is not configured on the switch, so it has no IGMP snooping row to edit. "+
				"Create the VLAN first (netgear_ms510txup_vlan); the switch adds the snooping row itself.",
				want.VLANID))
		return
	}
	plan.fromWire(*got)
}

func (r *ms510IGMPSnoopingVLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510IGMPSnoopingVLANModel
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

func (r *ms510IGMPSnoopingVLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510IGMPSnoopingVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetIGMPSnoopingVLAN(int(state.VLANID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read IGMP snooping for the VLAN", err.Error())
		return
	}
	// The row is gone because the VLAN is gone. Drop the resource from state
	// rather than erroring - the next plan then offers to recreate it, which
	// is what actually happened out there.
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510IGMPSnoopingVLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510IGMPSnoopingVLANModel
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

// Delete disables snooping on the VLAN and restores the shipped timers. The
// row itself belongs to the VLAN table and is not ours to remove.
func (r *ms510IGMPSnoopingVLANResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510IGMPSnoopingVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	off := ms510txup.IGMPSnoopingVLAN{
		VLANID:      int(state.VLANID.ValueInt64()),
		HostTimeout: 260,
		MaxResponse: 10,
		QueryIntvl:  60,
	}
	if err := r.client.SetIGMPSnoopingVLAN(off, false); err != nil {
		resp.Diagnostics.AddError("Could not disable IGMP snooping for the VLAN", err.Error())
	}
}

// ImportState takes the VLAN id:
//
//	terraform import netgear_ms510txup_igmp_snooping_vlan.storage 20
func (r *ms510IGMPSnoopingVLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vlan, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import this resource with the VLAN id, for example "+
				"`terraform import netgear_ms510txup_igmp_snooping_vlan.storage 20`. Got: "+req.ID)
		return
	}
	got, err := r.client.GetIGMPSnoopingVLAN(vlan)
	if err != nil {
		resp.Diagnostics.AddError("Could not read IGMP snooping for the VLAN", err.Error())
		return
	}
	if got == nil {
		resp.Diagnostics.AddError("The switch has no row for that VLAN",
			fmt.Sprintf("VLAN %d is not configured on the switch.", vlan))
		return
	}
	var state ms510IGMPSnoopingVLANModel
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vlan_id"), vlan)...)
}

// ms510Client pulls the switch client out of provider data, with the same
// error both MS510TXUP IGMP resources want.
func ms510Client(providerData any, diags diagSink, what string) *ms510txup.Client {
	if providerData == nil {
		return nil
	}
	c := clientsFrom(providerData)
	if c == nil {
		return nil
	}
	if c.MS510TXUP == nil {
		diags.AddError("MS510TXUP not configured",
			"This resource manages "+what+" on the MS510TXUP switch. Add an `ms510txup` block to the "+
				"provider, or set MS510TXUP_PASSWORD.")
		return nil
	}
	return c.MS510TXUP
}
