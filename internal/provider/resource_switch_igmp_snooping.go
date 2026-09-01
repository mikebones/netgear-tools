package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &switchIGMPSnoopingResource{}
	_ resource.ResourceWithImportState = &switchIGMPSnoopingResource{}
)

type switchIGMPSnoopingResource struct {
	client interface {
		Get(string, any) error
		Post(string, any, any) error
	}
}

func NewSwitchIGMPSnoopingResource() resource.Resource { return &switchIGMPSnoopingResource{} }

type switchIGMPSnoopingModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (r *switchIGMPSnoopingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_igmp_snooping"
}

func (r *switchIGMPSnoopingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "IGMP snooping on the switch.\n\n" +
			"With snooping off, the switch has no idea which ports care about which multicast groups, so it " +
			"floods every multicast frame to every port. On a flat network carrying mDNS/Bonjour, SSDP and Plex " +
			"GDM discovery that is a steady tax on every attached NIC, and it shows up as a climbing " +
			"broadcast/multicast receive count on ports that have no business seeing that traffic.\n\n" +
			"A settings singleton: destroying the resource turns snooping off rather than deleting anything.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
		},
	}
}

func (r *switchIGMPSnoopingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.XS508TM == nil {
		resp.Diagnostics.AddError("XS508TM not configured",
			"This resource manages the switch. Add an `xs508tm` block to the provider, or set XS508TM_PASSWORD.")
		return
	}
	r.client = c.XS508TM
}

// The device returns the whole settings object; only igsState is ours to
// change. Everything else is sent back exactly as read so a firmware field we
// do not model cannot be silently cleared.
type igmpSnoopingWire struct {
	Cfg map[string]any `json:"igmp_snpg_cfg"`
}

func (r *switchIGMPSnoopingResource) read() (bool, error) {
	var got igmpSnoopingWire
	if err := r.client.Get("igmp_snpg_cfg", &got); err != nil {
		return false, err
	}
	state, _ := got.Cfg["igsState"].(float64)
	return state == 1, nil
}

func (r *switchIGMPSnoopingResource) write(enabled bool) error {
	var got igmpSnoopingWire
	if err := r.client.Get("igmp_snpg_cfg", &got); err != nil {
		return err
	}
	cfg := got.Cfg
	if cfg == nil {
		cfg = map[string]any{}
	}
	if enabled {
		cfg["igsState"] = 1
	} else {
		cfg["igsState"] = 0
	}
	return r.client.Post("igmp_snpg_cfg", map[string]any{"igmp_snpg_cfg": cfg}, nil)
}

func (r *switchIGMPSnoopingResource) apply(plan *switchIGMPSnoopingModel, diags interface {
	AddError(string, string)
}) {
	if err := r.write(plan.Enabled.ValueBool()); err != nil {
		diags.AddError("Could not set IGMP snooping", err.Error())
		return
	}
	got, err := r.read()
	if err != nil {
		diags.AddError("Could not read back IGMP snooping", err.Error())
		return
	}
	plan.Enabled = types.BoolValue(got)
}

func (r *switchIGMPSnoopingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchIGMPSnoopingModel
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

func (r *switchIGMPSnoopingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchIGMPSnoopingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read IGMP snooping", err.Error())
		return
	}
	state.Enabled = types.BoolValue(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *switchIGMPSnoopingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchIGMPSnoopingModel
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

// Delete disables snooping, which is the state the switch shipped in. Leaving
// it enabled after the resource is removed would be the surprising outcome.
func (r *switchIGMPSnoopingResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.write(false); err != nil {
		resp.Diagnostics.AddError("Could not disable IGMP snooping", err.Error())
	}
}

func (r *switchIGMPSnoopingResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read IGMP snooping", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &switchIGMPSnoopingModel{Enabled: types.BoolValue(got)})...)
}
