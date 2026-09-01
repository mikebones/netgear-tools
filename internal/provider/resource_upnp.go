package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &upnpResource{}
	_ resource.ResourceWithImportState = &upnpResource{}
)

type upnpResource struct {
	client *pr60x.Client
}

func NewUPnPResource() resource.Resource { return &upnpResource{} }

type upnpModel struct {
	Enabled           types.Bool  `tfsdk:"enabled"`
	NotifyIntervalSec types.Int64 `tfsdk:"notify_interval_seconds"`
	NotifyTTL         types.Int64 `tfsdk:"notify_ttl"`
}

func (r *upnpResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_upnp"
}

func (r *upnpResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "UPnP IGD, which lets any device on the LAN open its own WAN ports without asking.\n\n" +
			"Declaring this with `enabled = false` is the point: it turns \"UPnP is off\" from something you " +
			"believe into something Terraform re-asserts, so a firmware upgrade or someone clicking around the " +
			"web UI shows up as drift. If UPnP is on, the port-forwarding rules you manage here are only part of " +
			"what is actually exposed - check `pr60x_upnp_port_map_entries` in the exporter for what it has opened.\n\n" +
			"A settings singleton: destroying the resource disables UPnP rather than deleting anything.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"notify_interval_seconds": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(1800),
				Description: "SSDP advertisement interval. Only relevant when enabled.",
			},
			"notify_ttl": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(4),
				Description: "SSDP advertisement TTL. Only relevant when enabled.",
			},
		},
	}
}

func (r *upnpResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m upnpModel) toAPI() pr60x.UPnPSettings {
	enabled := int64(0)
	if m.Enabled.ValueBool() {
		enabled = 1
	}
	return pr60x.UPnPSettings{
		Enabled:           enabled,
		NotifyIntervalSec: m.NotifyIntervalSec.ValueInt64(),
		NotifyTTL:         m.NotifyTTL.ValueInt64(),
	}
}

func applyUPnP(dst *upnpModel, src *pr60x.UPnPSettings) {
	dst.Enabled = types.BoolValue(src.Enabled != 0)
	dst.NotifyIntervalSec = types.Int64Value(src.NotifyIntervalSec)
	dst.NotifyTTL = types.Int64Value(src.NotifyTTL)
}

func (r *upnpResource) write(plan *upnpModel, diags interface{ AddError(string, string) }) {
	if err := r.client.SetUPnPSettings(plan.toAPI()); err != nil {
		diags.AddError("Could not set UPnP settings", err.Error())
		return
	}
	got, err := r.client.GetUPnPSettings()
	if err != nil {
		diags.AddError("Could not read back UPnP settings", err.Error())
		return
	}
	applyUPnP(plan, got)
}

func (r *upnpResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan upnpModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *upnpResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state upnpModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetUPnPSettings()
	if err != nil {
		resp.Diagnostics.AddError("Could not read UPnP settings", err.Error())
		return
	}
	applyUPnP(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *upnpResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan upnpModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete turns UPnP off. Leaving it on after the resource is removed would be
// the surprising outcome for a resource whose purpose is keeping it off.
func (r *upnpResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state upnpModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	off := state.toAPI()
	off.Enabled = 0
	if err := r.client.SetUPnPSettings(off); err != nil {
		resp.Diagnostics.AddError("Could not disable UPnP", err.Error())
	}
}

func (r *upnpResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetUPnPSettings()
	if err != nil {
		resp.Diagnostics.AddError("Could not read UPnP settings", err.Error())
		return
	}
	var state upnpModel
	applyUPnP(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
