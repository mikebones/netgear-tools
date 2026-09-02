package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/xs508tm"
)

var (
	_ resource.Resource                = &switchPortMTUResource{}
	_ resource.ResourceWithImportState = &switchPortMTUResource{}
)

type switchPortMTUResource struct {
	client *xs508tm.Client
}

func NewSwitchPortMTUResource() resource.Resource { return &switchPortMTUResource{} }

type switchPortMTUModel struct {
	Port types.Int64 `tfsdk:"port"`
	MTU  types.Int64 `tfsdk:"mtu"`
}

func (r *switchPortMTUResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_port_mtu"
}

func (r *switchPortMTUResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Maximum frame size for one switch port - what the CLI calls `mtu` and the REST API " +
			"reports as `maxFrmsz`.\n\n" +
			"**This resource writes over SSH, not REST.** The REST route exposes the value read-only: every " +
			"write shape is refused with errCode 255 while other routes accept writes in the same session. " +
			"The provider therefore needs the switch reachable on port 22 with the same credentials.\n\n" +
			"The CLI accepts 1500-9198. Note the ceiling is 9198, not the 9216 a jumbo-frame ceiling is usually " +
			"quoted as, so a 9000-byte payload fits but the round number above it does not.\n\n" +
			"Each change is saved with `write memory`. Without that the CLI writes only the running config and " +
			"the setting disappears at the next reboot.\n\n" +
			"A port whose frame size is lower than the traffic sent to it does not negotiate anything down - it " +
			"drops the oversized frames. Raise every port along a jumbo path, or none of them.",
		Attributes: map[string]schema.Attribute{
			"port": schema.Int64Attribute{
				Required:    true,
				Description: "Front-panel port number, as in the CLI's `0/<port>`.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"mtu": schema.Int64Attribute{
				Required:    true,
				Description: "Maximum frame size, 1500-9198.",
			},
		},
	}
}

func (r *switchPortMTUResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *switchPortMTUResource) apply(plan *switchPortMTUModel, diags interface {
	AddError(string, string)
}) {
	port := int(plan.Port.ValueInt64())
	if err := r.client.SetPortMTU(port, int(plan.MTU.ValueInt64())); err != nil {
		diags.AddError(fmt.Sprintf("Could not set the MTU on port 0/%d", port), err.Error())
		return
	}
	got, err := r.client.GetPortMTU(port)
	if err != nil {
		diags.AddError(fmt.Sprintf("Could not read back the MTU on port 0/%d", port), err.Error())
		return
	}
	plan.MTU = types.Int64Value(int64(got))
}

func (r *switchPortMTUResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchPortMTUModel
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

func (r *switchPortMTUResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchPortMTUModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetPortMTU(int(state.Port.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port MTU", err.Error())
		return
	}
	state.MTU = types.Int64Value(int64(got))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *switchPortMTUResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchPortMTUModel
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

// Delete returns the port to the shipped 1500 rather than leaving a jumbo port
// behind with nothing describing it.
func (r *switchPortMTUResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state switchPortMTUModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetPortMTU(int(state.Port.ValueInt64()), xs508tm.DefaultPortMTU); err != nil {
		resp.Diagnostics.AddError("Could not restore the port MTU", err.Error())
	}
}

func (r *switchPortMTUResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	port, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import by front-panel port number, for example `terraform import ... 2`. Got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
}
