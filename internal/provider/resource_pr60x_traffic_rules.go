package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &pr60xTrafficRulesResource{}
	_ resource.ResourceWithImportState = &pr60xTrafficRulesResource{}
)

type pr60xTrafficRulesResource struct {
	client *pr60x.Client
}

func NewPR60XTrafficRulesResource() resource.Resource { return &pr60xTrafficRulesResource{} }

type trafficRuleModel struct {
	Name                 types.String `tfsdk:"name"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	Action               types.String `tfsdk:"action"`
	Service              types.String `tfsdk:"service"`
	Schedule             types.String `tfsdk:"schedule"`
	SourceInterface      types.String `tfsdk:"source_interface"`
	DestinationInterface types.String `tfsdk:"destination_interface"`
	Source               types.String `tfsdk:"source"`
	Destination          types.String `tfsdk:"destination"`
}

type pr60xTrafficRulesModel struct {
	ID    types.String       `tfsdk:"id"`
	Rules []trafficRuleModel `tfsdk:"rule"`
}

func (r *pr60xTrafficRulesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_traffic_rules"
}

func (r *pr60xTrafficRulesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The router's complete, ordered traffic-rule list (Firewall > Traffic Rules).\n\n" +
			"AUTHORITATIVE: rules not listed here are deleted. Order is priority - the first matching rule " +
			"wins - so put the narrow allows before the broad deny. Any change replaces the whole list (delete " +
			"all, add in order), leaving a sub-second window with no rules.\n\n" +
			"Interfaces are `vlan<N>` (VLAN 1 is `vlan1`; `lan` is rejected), `wan`, or `Any`. A rule between " +
			"two VLANs is rejected unless `inter_vlan_routing` is on for both (`netgear_pr60x_vlan`).\n\n" +
			"Addresses: `any`, a single IP, a CIDR subnet, or `start-end`.\n\n" +
			"Destroying the resource deletes every rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "Always `traffic_rules`."},
		},
		Blocks: map[string]schema.Block{
			"rule": schema.ListNestedBlock{
				Description: "One rule. Listed in priority order.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name":    schema.StringAttribute{Required: true, Description: "Unique name, up to 64 characters, no ':'."},
						"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
						"action":  schema.StringAttribute{Required: true, Description: "`allow` or `deny`."},
						"service": schema.StringAttribute{Required: true, Description: "Service profile name, e.g. `All Traffic`, `DNS-UDP`, or a custom one."},
						"schedule": schema.StringAttribute{
							Optional: true, Computed: true, Default: stringdefault.StaticString("Always"),
							Description: "Schedule profile name.",
						},
						"source_interface":      schema.StringAttribute{Required: true},
						"destination_interface": schema.StringAttribute{Required: true},
						"source": schema.StringAttribute{
							Optional: true, Computed: true, Default: stringdefault.StaticString("any"),
						},
						"destination": schema.StringAttribute{
							Optional: true, Computed: true, Default: stringdefault.StaticString("any"),
						},
					},
				},
			},
		},
	}
}

func (r *pr60xTrafficRulesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func toRules(in []trafficRuleModel, diags *diag.Diagnostics) []pr60x.TrafficRule {
	out := make([]pr60x.TrafficRule, 0, len(in))
	for _, m := range in {
		src, err := pr60x.ParseAddress(m.Source.ValueString())
		if err != nil {
			diags.AddError("Invalid source in rule "+m.Name.ValueString(), err.Error())
			continue
		}
		dst, err := pr60x.ParseAddress(m.Destination.ValueString())
		if err != nil {
			diags.AddError("Invalid destination in rule "+m.Name.ValueString(), err.Error())
			continue
		}
		action := m.Action.ValueString()
		if action != "allow" && action != "deny" {
			diags.AddError("Invalid action in rule "+m.Name.ValueString(), `action must be "allow" or "deny"`)
			continue
		}
		out = append(out, pr60x.TrafficRule{
			Name:                 m.Name.ValueString(),
			Enabled:              m.Enabled.ValueBool(),
			Allow:                action == "allow",
			Service:              m.Service.ValueString(),
			Schedule:             m.Schedule.ValueString(),
			SourceInterface:      m.SourceInterface.ValueString(),
			DestinationInterface: m.DestinationInterface.ValueString(),
			Source:               src,
			Destination:          dst,
		})
	}
	return out
}

// fromRules builds state, keeping the configured spelling of an address when it
// parses to the same value the device returned.
func fromRules(got []pr60x.TrafficRule, prior []trafficRuleModel) []trafficRuleModel {
	out := make([]trafficRuleModel, 0, len(got))
	for i, r := range got {
		action := "deny"
		if r.Allow {
			action = "allow"
		}
		src, dst := r.Source.String(), r.Destination.String()
		if i < len(prior) {
			if a, err := pr60x.ParseAddress(prior[i].Source.ValueString()); err == nil && a == r.Source {
				src = prior[i].Source.ValueString()
			}
			if a, err := pr60x.ParseAddress(prior[i].Destination.ValueString()); err == nil && a == r.Destination {
				dst = prior[i].Destination.ValueString()
			}
		}
		out = append(out, trafficRuleModel{
			Name:                 types.StringValue(r.Name),
			Enabled:              types.BoolValue(r.Enabled),
			Action:               types.StringValue(action),
			Service:              types.StringValue(r.Service),
			Schedule:             types.StringValue(r.Schedule),
			SourceInterface:      types.StringValue(r.SourceInterface),
			DestinationInterface: types.StringValue(r.DestinationInterface),
			Source:               types.StringValue(src),
			Destination:          types.StringValue(dst),
		})
	}
	return out
}

func (r *pr60xTrafficRulesResource) apply(plan *pr60xTrafficRulesModel, diags *diag.Diagnostics) {
	rules := toRules(plan.Rules, diags)
	if diags.HasError() {
		return
	}
	if err := r.client.ReplaceTrafficRules(rules); err != nil {
		diags.AddError("Could not write traffic rules", err.Error())
		return
	}
	got, err := r.client.ListTrafficRules()
	if err != nil {
		diags.AddError("Could not read back traffic rules", err.Error())
		return
	}
	plan.Rules = fromRules(got, plan.Rules)
	plan.ID = types.StringValue("traffic_rules")
}

func (r *pr60xTrafficRulesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pr60xTrafficRulesModel
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

func (r *pr60xTrafficRulesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pr60xTrafficRulesModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.ListTrafficRules()
	if err != nil {
		resp.Diagnostics.AddError("Could not read traffic rules", err.Error())
		return
	}
	state.Rules = fromRules(got, state.Rules)
	state.ID = types.StringValue("traffic_rules")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pr60xTrafficRulesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pr60xTrafficRulesModel
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

func (r *pr60xTrafficRulesResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.ReplaceTrafficRules(nil); err != nil {
		resp.Diagnostics.AddError("Could not delete traffic rules", err.Error())
	}
}

func (r *pr60xTrafficRulesResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &pr60xTrafficRulesModel{ID: types.StringValue("traffic_rules")})...)
}
