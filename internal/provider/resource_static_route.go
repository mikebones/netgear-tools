package provider

import (
	"netgear-tools/internal/pr60x"

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &staticRouteResource{}
	_ resource.ResourceWithImportState = &staticRouteResource{}
)

type staticRouteResource struct {
	client *pr60x.Client
}

func NewStaticRouteResource() resource.Resource {
	return &staticRouteResource{}
}

type staticRouteModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Destination types.String `tfsdk:"destination"`
	Netmask     types.String `tfsdk:"netmask"`
	Gateway     types.String `tfsdk:"gateway"`
	Metric      types.Int64  `tfsdk:"metric"`
	Interface   types.String `tfsdk:"interface"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (r *staticRouteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_static_route"
}

func (r *staticRouteResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A static route on the router.\n\n" +
			"UNVERIFIED: the device currently has no static routes, so these field names come from the web UI's " +
			"form rather than from an observed response, and the write calls have not been exercised. Create one " +
			"throwaway route and confirm it reads back correctly before depending on this.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				Description:   "Device-assigned route id.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Label for the route.",
			},
			"destination": schema.StringAttribute{
				Required:    true,
				Description: "Destination network address, e.g. 10.44.0.0.",
			},
			"netmask": schema.StringAttribute{
				Required:    true,
				Description: "Destination netmask, e.g. 255.255.255.0.",
			},
			"gateway": schema.StringAttribute{
				Required:    true,
				Description: "Next hop.",
			},
			"metric": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(1),
				Description: "Route metric; lower wins.",
			},
			"interface": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("lan"),
				Description: "Egress interface, e.g. lan or wan.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
		},
	}
}

func (r *staticRouteResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m staticRouteModel) toAPI() pr60x.StaticRoute {
	enabled := int64(0)
	if m.Enabled.ValueBool() {
		enabled = 1
	}
	return pr60x.StaticRoute{
		ID:          m.ID.ValueInt64(),
		Name:        m.Name.ValueString(),
		Destination: m.Destination.ValueString(),
		Netmask:     m.Netmask.ValueString(),
		Gateway:     m.Gateway.ValueString(),
		Metric:      m.Metric.ValueInt64(),
		Interface:   m.Interface.ValueString(),
		Enabled:     enabled,
	}
}

func applyStaticRoute(dst *staticRouteModel, src *pr60x.StaticRoute) {
	dst.ID = types.Int64Value(src.ID)
	dst.Name = types.StringValue(src.Name)
	dst.Destination = types.StringValue(src.Destination)
	dst.Netmask = types.StringValue(src.Netmask)
	dst.Gateway = types.StringValue(src.Gateway)
	dst.Metric = types.Int64Value(src.Metric)
	dst.Interface = types.StringValue(src.Interface)
	dst.Enabled = types.BoolValue(src.Enabled != 0)
}

func (r *staticRouteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan staticRouteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	want := plan.toAPI()
	id, err := r.client.AddStaticRoute(want)
	if err != nil {
		resp.Diagnostics.AddError("Could not create static route", err.Error())
		return
	}

	created, err := r.client.GetStaticRouteByID(id)
	if err != nil {
		resp.Diagnostics.AddError("Could not read back created static route", err.Error())
		return
	}
	if created == nil {
		resp.Diagnostics.AddError(
			"Static route was not created",
			fmt.Sprintf("addStaticRoutes reported success but no route with id %d exists. The field names for "+
				"this resource are unverified - see the resource description.", id),
		)
		return
	}

	applyStaticRoute(&plan, created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *staticRouteResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state staticRouteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	route, err := r.client.GetStaticRouteByID(state.ID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Could not read static route", err.Error())
		return
	}
	if route == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	applyStaticRoute(&state, route)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *staticRouteResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state staticRouteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = state.ID
	if err := r.client.EditStaticRoute(plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Could not update static route", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *staticRouteResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state staticRouteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteStaticRoute(state.ID.ValueInt64()); err != nil {
		resp.Diagnostics.AddError("Could not delete static route", err.Error())
	}
}

func (r *staticRouteResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import id",
			fmt.Sprintf("Expected a numeric static route id, got %q.", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
