package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &portForwardingRuleResource{}
	_ resource.ResourceWithImportState = &portForwardingRuleResource{}
)

type portForwardingRuleResource struct {
	client *client
}

func NewPortForwardingRuleResource() resource.Resource {
	return &portForwardingRuleResource{}
}

func (r *portForwardingRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_port_forwarding_rule"
}

func (r *portForwardingRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A WAN-to-LAN port-forwarding rule. This exposes an internal host to the internet, so treat " +
			"every instance of it as a deliberate security decision.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				Description:   "Device-assigned rule id.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"external_service": schema.StringAttribute{
				Required: true,
				Description: "Name of the service profile matched on the WAN side. Must already exist - reference " +
					"a pr60x_service_profile's name attribute so Terraform orders them correctly.",
			},
			"internal_service": schema.StringAttribute{
				Required: true,
				Description: "Name of the service profile the traffic is translated to on the LAN side. Set it to a " +
					"different profile than external_service to do port translation; the device has no separate " +
					"external-port field.",
			},
			"dest_ip_address": schema.StringAttribute{
				Required:    true,
				Description: "Internal IPv4 address to forward to.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the rule is active.",
			},
			"src_ip_address": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("Any"),
				Description: "Permitted source address, or \"Any\". Narrowing this is the cheapest way to reduce exposure.",
			},
			"wan_input_interface": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("wan"),
				Description: "Which WAN the rule applies to: wan, wan1 or wan2.",
			},
			"wan_ip_address": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Specific WAN address to match. Empty means the interface's current address.",
			},
		},
	}
}

func (r *portForwardingRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client)
}

func (m portForwardingRuleModel) toAPI() portForwardingRule {
	enabled := int64(0)
	if m.Enabled.ValueBool() {
		enabled = 1
	}
	return portForwardingRule{
		ID:                m.ID.ValueInt64(),
		Enabled:           enabled,
		ExternalService:   m.ExternalService.ValueString(),
		InternalService:   m.InternalService.ValueString(),
		DestIPAddress:     m.DestIPAddress.ValueString(),
		SrcIPAddress:      m.SrcIPAddress.ValueString(),
		WANInputInterface: m.WANInputInterface.ValueString(),
		WANIPAddress:      m.WANIPAddress.ValueString(),
	}
}

func applyPortForwardingRule(dst *portForwardingRuleModel, src *portForwardingRule) {
	dst.ID = types.Int64Value(src.ID)
	dst.Enabled = types.BoolValue(src.Enabled != 0)
	dst.ExternalService = types.StringValue(src.ExternalService)
	dst.InternalService = types.StringValue(src.InternalService)
	dst.DestIPAddress = types.StringValue(src.DestIPAddress)
	dst.SrcIPAddress = types.StringValue(src.SrcIPAddress)
	dst.WANInputInterface = types.StringValue(src.WANInputInterface)
	dst.WANIPAddress = types.StringValue(src.WANIPAddress)
}

// matches identifies a rule by its natural key. The device assigns ids on
// create and does not return them, so this is how a freshly created rule is
// located to recover its id.
func matches(r portForwardingRule, want portForwardingRule) bool {
	return r.ExternalService == want.ExternalService &&
		r.InternalService == want.InternalService &&
		r.DestIPAddress == want.DestIPAddress &&
		r.WANInputInterface == want.WANInputInterface
}

func (r *portForwardingRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan portForwardingRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	want := plan.toAPI()

	// Both referenced service profiles must exist first - the device stores
	// them by name and will otherwise create a rule pointing at nothing.
	for _, name := range []string{want.ExternalService, want.InternalService} {
		profile, err := r.client.getServiceProfileByName(name)
		if err != nil {
			resp.Diagnostics.AddError("Could not verify service profile", err.Error())
			return
		}
		if profile == nil {
			resp.Diagnostics.AddError(
				"Referenced service profile does not exist",
				fmt.Sprintf("No service profile named %q on the router. Create a pr60x_service_profile for it "+
					"and reference that resource's name attribute so Terraform creates them in order.", name),
			)
			return
		}
	}

	before, err := r.client.listPortForwardingRules()
	if err != nil {
		resp.Diagnostics.AddError("Could not list existing port-forwarding rules", err.Error())
		return
	}
	for _, existing := range before {
		if matches(existing, want) {
			resp.Diagnostics.AddError(
				"Port-forwarding rule already exists",
				fmt.Sprintf("Rule id %d already forwards %s to %s. Import it with: "+
					"terraform import pr60x_port_forwarding_rule.<name> %d",
					existing.ID, existing.ExternalService, existing.DestIPAddress, existing.ID),
			)
			return
		}
	}

	if _, err := r.client.addPortForwardingRule(want); err != nil {
		resp.Diagnostics.AddError("Could not create port-forwarding rule", err.Error())
		return
	}

	after, err := r.client.listPortForwardingRules()
	if err != nil {
		resp.Diagnostics.AddError("Could not read back created port-forwarding rule", err.Error())
		return
	}
	for i := range after {
		if matches(after[i], want) {
			applyPortForwardingRule(&plan, &after[i])
			resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
			return
		}
	}
	resp.Diagnostics.AddError(
		"Port-forwarding rule was not created",
		"addPortForwardingRules reported success but the rule is not present. This usually means the write "+
			"payload shape is wrong - see the write-shape note in client.go and run scripts/roundtrip.py.",
	)
}

func (r *portForwardingRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state portForwardingRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, err := r.client.getPortForwardingRuleByID(state.ID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Could not read port-forwarding rule", err.Error())
		return
	}
	if rule == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	applyPortForwardingRule(&state, rule)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *portForwardingRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state portForwardingRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = state.ID
	if err := r.client.editPortForwardingRule(plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Could not update port-forwarding rule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *portForwardingRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state portForwardingRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.deletePortForwardingRule(state.ID.ValueInt64()); err != nil {
		resp.Diagnostics.AddError("Could not delete port-forwarding rule", err.Error())
	}
}

func (r *portForwardingRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import id",
			fmt.Sprintf("Expected a numeric rule id, got %q. "+
				"Use the pr60x_port_forwarding_rules data source to list them.", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
