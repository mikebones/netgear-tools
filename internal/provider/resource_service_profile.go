package provider

import (
	"terraform-provider-pr60x/internal/pr60x"

	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &serviceProfileResource{}
	_ resource.ResourceWithImportState = &serviceProfileResource{}
)

type serviceProfileResource struct {
	client *pr60x.Client
}

func NewServiceProfileResource() resource.Resource {
	return &serviceProfileResource{}
}

func (r *serviceProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_profile"
}

func (r *serviceProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A named protocol/port definition on the router. Port-forwarding rules reference these by " +
			"name, so a forward always needs its service profile to exist first.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				Description:   "Device-assigned profile id.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				Description: "Profile name. This is the identity a port-forwarding rule refers to, so keep it " +
					"stable and descriptive, e.g. WG or TRANSMISSION-TV.",
			},
			"proto": schema.StringAttribute{
				Required:    true,
				Description: "One of all, tcp, udp, icmp.",
			},
			"start_port": schema.Int64Attribute{
				Optional:    true,
				Description: "First port in the range. Required for tcp and udp; omit for all and icmp.",
			},
			"end_port": schema.Int64Attribute{
				Optional:    true,
				Description: "Last port in the range. Set equal to start_port for a single port.",
			},
			"icmp_type": schema.Int64Attribute{
				Optional:    true,
				Description: "ICMP type number. Only meaningful when proto is icmp.",
			},
		},
	}
}

func (r *serviceProfileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*pr60x.Client)
}

// toAPI converts plan/state into the wire struct, honouring the device's
// convention that port fields are absent for proto all/icmp.
func (m serviceProfileModel) toAPI() pr60x.ServiceProfile {
	p := pr60x.ServiceProfile{
		ID:    m.ID.ValueInt64(),
		Name:  m.Name.ValueString(),
		Proto: m.Proto.ValueString(),
	}
	if !m.StartPort.IsNull() && !m.StartPort.IsUnknown() {
		v := m.StartPort.ValueInt64()
		p.StartPort = &v
	}
	if !m.EndPort.IsNull() && !m.EndPort.IsUnknown() {
		v := m.EndPort.ValueInt64()
		p.EndPort = &v
	}
	if !m.ICMPType.IsNull() && !m.ICMPType.IsUnknown() {
		v := m.ICMPType.ValueInt64()
		p.ICMPType = &v
	}
	return p
}

func applyServiceProfile(dst *serviceProfileModel, src *pr60x.ServiceProfile) {
	dst.ID = types.Int64Value(src.ID)
	dst.Name = types.StringValue(src.Name)
	dst.Proto = types.StringValue(src.Proto)
	dst.StartPort = optionalInt64(src.StartPort)
	dst.EndPort = optionalInt64(src.EndPort)
	dst.ICMPType = optionalInt64(src.ICMPType)
}

func optionalInt64(p *int64) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*p)
}

func (r *serviceProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()

	existing, err := r.client.GetServiceProfileByName(name)
	if err != nil {
		resp.Diagnostics.AddError("Could not check existing service profiles", err.Error())
		return
	}
	if existing != nil {
		resp.Diagnostics.AddError(
			"Service profile already exists",
			fmt.Sprintf("A service profile named %q already exists on the router (id %d). "+
				"Import it with: terraform import pr60x_service_profile.<name> %d",
				name, existing.ID, existing.ID),
		)
		return
	}

	if _, err := r.client.AddServiceProfile(plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Could not create service profile", err.Error())
		return
	}

	// The add call returns only {"result":0}, so read the profile back to
	// confirm it landed and to capture exactly what the device stored.
	created, err := r.client.GetServiceProfileByName(name)
	if err != nil {
		resp.Diagnostics.AddError("Could not read back created service profile", err.Error())
		return
	}
	if created == nil {
		resp.Diagnostics.AddError(
			"Service profile was not created",
			fmt.Sprintf("addServiceProfiles reported success but no profile named %q exists. "+
				"This usually means the write payload shape is wrong - see the write-shape note in client.go "+
				"and run scripts/roundtrip.py to confirm it.", name),
		)
		return
	}

	applyServiceProfile(&plan, created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	all, err := r.client.ListServiceProfiles()
	if err != nil {
		resp.Diagnostics.AddError("Could not read service profiles", err.Error())
		return
	}

	wantID := state.ID.ValueInt64()
	for i := range all {
		if all[i].ID == wantID {
			applyServiceProfile(&state, &all[i])
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	// Gone from the device - drop it so Terraform plans a recreate.
	resp.State.RemoveResource(ctx)
}

func (r *serviceProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state serviceProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = state.ID
	if err := r.client.EditServiceProfile(plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Could not update service profile", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Refuse to delete a profile that a port-forwarding rule still references.
	// The device stores that reference by name, so removing the profile would
	// leave a dangling rule rather than failing cleanly.
	rules, err := r.client.ListPortForwardingRules()
	if err != nil {
		resp.Diagnostics.AddError("Could not check port-forwarding rules before delete", err.Error())
		return
	}
	name := state.Name.ValueString()
	for _, rule := range rules {
		if rule.ExternalService == name || rule.InternalService == name {
			resp.Diagnostics.AddError(
				"Service profile is still in use",
				fmt.Sprintf("Port-forwarding rule id %d references service profile %q. "+
					"Destroy or retarget that rule first.", rule.ID, name),
			)
			return
		}
	}

	if err := r.client.DeleteServiceProfile(state.ID.ValueInt64()); err != nil {
		resp.Diagnostics.AddError("Could not delete service profile", err.Error())
	}
}

func (r *serviceProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import id",
			fmt.Sprintf("Expected a numeric service profile id, got %q. "+
				"Use the pr60x_service_profiles data source to find it.", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
