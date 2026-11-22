package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510PortVLANResource{}
	_ resource.ResourceWithImportState = &ms510PortVLANResource{}
)

type ms510PortVLANResource struct {
	client *ms510txup.Client
}

func NewMS510PortVLANResource() resource.Resource { return &ms510PortVLANResource{} }

type ms510PortVLANModel struct {
	Port    types.Int64 `tfsdk:"port"`
	PVID    types.Int64 `tfsdk:"pvid"`
	Members types.List  `tfsdk:"member_vlans"`
	Tagged  types.List  `tfsdk:"tagged_vlans"`
}

func (r *ms510PortVLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_port_vlan"
}

func (r *ms510PortVLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One port's PVID and complete VLAN membership (Switching > VLAN > Port PVID Configuration).\n\n" +
			"This is the resource that MOVES a device: changing `pvid` changes which VLAN the port's untagged " +
			"traffic lands in, so pointing it at the wrong port cuts that port off. On this switch that can " +
			"be a cluster node - check the MAC table first.\n\n" +
			"`member_vlans` is the port's whole membership; members not in `tagged_vlans` are untagged. An " +
			"access port is `pvid = 30`, `member_vlans = [30]`. Keep `netgear_ms510txup_vlan` consistent: a " +
			"port made an untagged member of VLAN N here must also be in that VLAN's `untagged_ports`, or the " +
			"next apply of the VLAN resource removes it again.\n\n" +
			"Destroying the resource returns the port to the factory state (PVID 1, untagged member of VLAN 1 " +
			"only), which is the rollback for a device moved off VLAN 1.",
		Attributes: map[string]schema.Attribute{
			"port": schema.Int64Attribute{
				Required:      true,
				Description:   "Front-panel port number, 1-10.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"pvid": schema.Int64Attribute{
				Required:    true,
				Description: "VLAN that untagged frames arriving on the port are placed in. Must be in member_vlans.",
			},
			"member_vlans": schema.ListAttribute{
				Required:    true,
				ElementType: types.Int64Type,
				Description: "Every VLAN the port belongs to, tagged or not.",
			},
			"tagged_vlans": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.Int64Type,
				Default:     listdefault.StaticValue(types.ListValueMust(types.Int64Type, []attr.Value{})),
				Description: "The members the port sends tagged. Default none.",
			},
		},
	}
}

func (r *ms510PortVLANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.MS510TXUP == nil {
		resp.Diagnostics.AddError("MS510TXUP not configured",
			"This resource manages the PoE switch. Add an `ms510txup` block to the provider, or set MS510TXUP_PASSWORD.")
		return
	}
	r.client = c.MS510TXUP
}

// parseVLANList reads the switch's "1,20" / "1-3,30" / "" notation.
func parseVLANList(s string) ([]int64, error) {
	var out []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.ParseInt(strings.TrimSpace(lo), 10, 64)
			b, err2 := strconv.ParseInt(strings.TrimSpace(hi), 10, 64)
			if err1 != nil || err2 != nil || b < a {
				return nil, fmt.Errorf("bad VLAN range %q", part)
			}
			for v := a; v <= b; v++ {
				out = append(out, v)
			}
			continue
		}
		v, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad VLAN id %q", part)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func formatVLANList(v []int64) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, strconv.FormatInt(x, 10))
	}
	return strings.Join(parts, ",")
}

func listInts(ctx context.Context, l types.List, diags *diag.Diagnostics) []int64 {
	var out []int64
	if l.IsNull() || l.IsUnknown() {
		return out
	}
	diags.Append(l.ElementsAs(ctx, &out, false)...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func intsList(v []int64) types.List {
	vals := make([]attr.Value, 0, len(v))
	for _, x := range v {
		vals = append(vals, types.Int64Value(x))
	}
	return types.ListValueMust(types.Int64Type, vals)
}

func (r *ms510PortVLANResource) row(port int) (ms510txup.PortVLAN, error) {
	rows, err := r.client.ListPortVLANs()
	if err != nil {
		return ms510txup.PortVLAN{}, err
	}
	if port < 1 || port > len(rows) {
		return ms510txup.PortVLAN{}, fmt.Errorf("port %d not in the switch's %d port rows", port, len(rows))
	}
	return rows[port-1], nil
}

// fill sets the model from a device row.
func fill(m *ms510PortVLANModel, row ms510txup.PortVLAN, diags *diag.Diagnostics) {
	members, err := parseVLANList(row.Members)
	if err != nil {
		diags.AddError("Could not parse port membership", err.Error())
		return
	}
	tagged, err := parseVLANList(row.Tagged)
	if err != nil {
		diags.AddError("Could not parse port tagged membership", err.Error())
		return
	}
	m.PVID = types.Int64Value(int64(row.PVID))
	m.Members = intsList(members)
	m.Tagged = intsList(tagged)
}

func (r *ms510PortVLANResource) write(ctx context.Context, plan *ms510PortVLANModel, diags *diag.Diagnostics) {
	port := int(plan.Port.ValueInt64())
	members := listInts(ctx, plan.Members, diags)
	tagged := listInts(ctx, plan.Tagged, diags)
	if diags.HasError() {
		return
	}
	pvid := plan.PVID.ValueInt64()
	in := map[int64]bool{}
	for _, v := range members {
		in[v] = true
	}
	if !in[pvid] {
		diags.AddError("Invalid port VLAN config", fmt.Sprintf("pvid %d must be one of member_vlans %v", pvid, members))
		return
	}
	for _, v := range tagged {
		if !in[v] {
			diags.AddError("Invalid port VLAN config", fmt.Sprintf("tagged VLAN %d is not in member_vlans %v", v, members))
			return
		}
	}

	cur, err := r.row(port)
	if err != nil {
		diags.AddError("Could not read the port before writing", err.Error())
		return
	}
	cur.PVID, cur.Members, cur.Tagged = int(pvid), formatVLANList(members), formatVLANList(tagged)
	if err := r.client.SetPortVLAN(port, cur); err != nil {
		diags.AddError(fmt.Sprintf("Could not set VLANs on port %d", port), err.Error())
		return
	}
	// The firmware answers ok to writes it discarded, so the read-back is the
	// only real confirmation.
	got, err := r.row(port)
	if err != nil {
		diags.AddError("Could not read back the port", err.Error())
		return
	}
	fill(plan, got, diags)
}

func (r *ms510PortVLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510PortVLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ms510PortVLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510PortVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.row(int(state.Port.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port VLAN config", err.Error())
		return
	}
	fill(&state, got, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510PortVLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510PortVLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete puts the port back on VLAN 1 only - the factory state and the
// rollback for a device that was moved off it.
func (r *ms510PortVLANResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510PortVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan := ms510PortVLANModel{
		Port:    state.Port,
		PVID:    types.Int64Value(1),
		Members: intsList([]int64{1}),
		Tagged:  intsList(nil),
	}
	r.write(ctx, &plan, &resp.Diagnostics)
}

func (r *ms510PortVLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	port, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import by port number, for example `terraform import ... 6`. Got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
}
