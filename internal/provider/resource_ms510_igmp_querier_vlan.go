package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510IGMPQuerierVLANResource{}
	_ resource.ResourceWithImportState = &ms510IGMPQuerierVLANResource{}
)

type ms510IGMPQuerierVLANResource struct {
	client *ms510txup.Client
}

func NewMS510IGMPQuerierVLANResource() resource.Resource { return &ms510IGMPQuerierVLANResource{} }

type ms510IGMPQuerierVLANModel struct {
	VLANID  types.Int64 `tfsdk:"vlan_id"`
	Enabled types.Bool  `tfsdk:"enabled"`
}

func (r *ms510IGMPQuerierVLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_igmp_querier_vlan"
}

func (r *ms510IGMPQuerierVLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Whether the MS510TXUP originates IGMP queries on one VLAN.\n\n" +
			"**THIS IS THE SWITCH THAT MAKES SNOOPING DO ANYTHING**, and it is the third of three that all " +
			"have to line up: global snooping (`netgear_ms510txup_igmp_snooping`), per-VLAN snooping " +
			"(`netgear_ms510txup_igmp_snooping_vlan`), and this.\n\n" +
			"The global querier settings - address, version, intervals, and an enable flag - live at " +
			"Switching > Multicast > IGMP Snooping Querier. That flag reading 1 does NOT mean queries are " +
			"being sent. Measured on this switch: with the global flag on and no VLAN listed here, a " +
			"150-second capture on a cluster node saw ZERO IGMP packets on VLAN 1 and VLAN 20.\n\n" +
			"Without a querier nothing prompts hosts to send membership reports, so the snooping table never " +
			"populates and the switch falls back to flooding. Snooping is then inert rather than broken - " +
			"which is exactly why enabling snooping on its own moved no multicast counter here.\n\n" +
			"Enabling this makes the switch send general queries from the address configured globally. Where " +
			"a router already queries the segment, that is a second querier and IGMP elects the lower source " +
			"address - harmless but unnecessary. Check with a capture rather than assuming: the router on " +
			"this network does not query.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required:    true,
				Description: "VLAN to query on. Must already exist on the switch.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "Whether the switch sends IGMP queries on this VLAN. Setting this false " +
					"leaves snooping enabled but unfed, which reverts the VLAN to flooding.",
			},
		},
	}
}

func (r *ms510IGMPQuerierVLANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "the per-VLAN IGMP querier"); c != nil {
		r.client = c
	}
}

// apply writes and reads back. The device answers save_success for field sets
// it discards - two plausible field sets for this very command did exactly
// that before the working one was found - so the read-back is the only
// evidence the write took.
func (r *ms510IGMPQuerierVLANResource) apply(plan *ms510IGMPQuerierVLANModel, diags diagSink) {
	vlan := int(plan.VLANID.ValueInt64())
	want := plan.Enabled.ValueBool()
	if err := r.client.SetIGMPQuerierVLAN(vlan, want); err != nil {
		diags.AddError("Could not set the IGMP querier for the VLAN", err.Error())
		return
	}
	got, err := r.client.GetIGMPQuerierVLAN(vlan)
	if err != nil {
		diags.AddError("Could not read back the IGMP querier for the VLAN", err.Error())
		return
	}
	if got != want {
		diags.AddError("The switch did not accept the querier change",
			"Asked for enabled="+strconv.FormatBool(want)+" on VLAN "+strconv.Itoa(vlan)+
				" and the device still reports enabled="+strconv.FormatBool(got)+".\n\n"+
				"The usual cause is a VLAN the switch does not have - it accepts the write and silently "+
				"ignores it. Create the VLAN first (netgear_ms510txup_vlan).")
		return
	}
	plan.Enabled = types.BoolValue(got)
}

func (r *ms510IGMPQuerierVLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510IGMPQuerierVLANModel
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

func (r *ms510IGMPQuerierVLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510IGMPQuerierVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetIGMPQuerierVLAN(int(state.VLANID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read the IGMP querier for the VLAN", err.Error())
		return
	}
	state.Enabled = types.BoolValue(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510IGMPQuerierVLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510IGMPQuerierVLANModel
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

// Delete stops querying on the VLAN, which is the state the switch shipped in.
func (r *ms510IGMPQuerierVLANResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510IGMPQuerierVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetIGMPQuerierVLAN(int(state.VLANID.ValueInt64()), false); err != nil {
		resp.Diagnostics.AddError("Could not disable the IGMP querier for the VLAN", err.Error())
	}
}

// ImportState takes the VLAN id:
//
//	terraform import netgear_ms510txup_igmp_querier_vlan.lan 1
func (r *ms510IGMPQuerierVLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vlan, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import this resource with the VLAN id, for example "+
				"`terraform import netgear_ms510txup_igmp_querier_vlan.lan 1`. Got: "+req.ID)
		return
	}
	got, err := r.client.GetIGMPQuerierVLAN(vlan)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the IGMP querier for the VLAN", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &ms510IGMPQuerierVLANModel{
		VLANID:  types.Int64Value(int64(vlan)),
		Enabled: types.BoolValue(got),
	})...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vlan_id"), vlan)...)
}
