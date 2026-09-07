package provider

import (
	"context"

	"netgear-tools/internal/xs508tm"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &switchSSHResource{}
	_ resource.ResourceWithImportState = &switchSSHResource{}
)

type switchSSHResource struct{ client *xs508tm.Client }

func NewSwitchSSHResource() resource.Resource { return &switchSSHResource{} }

type switchSSHModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (r *switchSSHResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_ssh"
}

func (r *switchSSHResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The switch's SSH management service (ssh_global_cfg).\n\n" +
			"A factory-default switch ships with SSH OFF, which is exactly when it matters: SSH is the second " +
			"way in when the web server (lighttpd) wedges, and the only way to drive a recovery. Enabling it " +
			"here means a factory reset can be recovered without a console cable - see docs/xs508tm-recovery.md.\n\n" +
			"A settings singleton: destroying the resource turns SSH off, the state the switch shipped in.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
		},
	}
}

func (r *switchSSHResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *switchSSHResource) apply(plan *switchSSHModel, diags interface {
	AddError(string, string)
}) {
	if err := r.client.EnableSSH(plan.Enabled.ValueBool()); err != nil {
		diags.AddError("Could not set SSH service", err.Error())
		return
	}
	got, err := r.client.GetSSHConfig()
	if err != nil {
		diags.AddError("Could not read back SSH service", err.Error())
		return
	}
	plan.Enabled = types.BoolValue(got.Admin == 1)
}

func (r *switchSSHResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchSSHModel
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

func (r *switchSSHResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchSSHModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetSSHConfig()
	if err != nil {
		resp.Diagnostics.AddError("Could not read SSH service", err.Error())
		return
	}
	state.Enabled = types.BoolValue(got.Admin == 1)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *switchSSHResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchSSHModel
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

// Delete turns SSH off, the state the switch shipped in.
func (r *switchSSHResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.EnableSSH(false); err != nil {
		resp.Diagnostics.AddError("Could not disable SSH service", err.Error())
	}
}

func (r *switchSSHResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetSSHConfig()
	if err != nil {
		resp.Diagnostics.AddError("Could not read SSH service", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &switchSSHModel{Enabled: types.BoolValue(got.Admin == 1)})...)
}
