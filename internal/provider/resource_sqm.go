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

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &sqmResource{}
	_ resource.ResourceWithImportState = &sqmResource{}
)

type sqmResource struct {
	client *pr60x.Client
}

func NewSQMResource() resource.Resource { return &sqmResource{} }

type sqmModel struct {
	WANIndex     types.Int64  `tfsdk:"wan_index"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Download     types.Int64  `tfsdk:"download"`
	DownloadUnit types.String `tfsdk:"download_unit"`
	Upload       types.Int64  `tfsdk:"upload"`
	UploadUnit   types.String `tfsdk:"upload_unit"`
}

func (r *sqmResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_sqm"
}

func (r *sqmResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Smart Queue Management (traffic shaping) for one WAN. This is the fix for bufferbloat: " +
			"latency that spikes into the hundreds of milliseconds whenever the uplink is saturated, because " +
			"packets are sitting in an oversized buffer at the ISP.\n\n" +
			"Set download and upload slightly BELOW the line's real measured rate - around 85-95% is the usual " +
			"starting point. That is the whole trick: it keeps the queue on the router, where it can be managed, " +
			"instead of in the modem where it cannot. Measure the real rate first (the device's own speed test " +
			"will do) rather than using the number on the bill.\n\n" +
			"Note the device validates the range even when disabled: download and upload must fall between " +
			"300 Kbps and 5 Gbps, so a rate must be given regardless of `enabled`.",
		Attributes: map[string]schema.Attribute{
			"wan_index": schema.Int64Attribute{
				Required:      true,
				Description:   "Which WAN to shape. 0 is the primary.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"download": schema.Int64Attribute{
				Required:    true,
				Description: "Downstream rate to shape to. Must be 300 Kbps - 5 Gbps once converted by download_unit.",
			},
			"download_unit": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:     stringdefault.StaticString("Mbps"),
				Description: "Unit for download, e.g. Kbps, Mbps, Gbps.",
			},
			"upload": schema.Int64Attribute{
				Required:    true,
				Description: "Upstream rate to shape to. Usually the more important of the two for bufferbloat.",
			},
			"upload_unit": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:     stringdefault.StaticString("Mbps"),
				Description: "Unit for upload, e.g. Kbps, Mbps, Gbps.",
			},
		},
	}
}

func (r *sqmResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m sqmModel) toAPI() pr60x.SQMProfile {
	enabled := int64(0)
	if m.Enabled.ValueBool() {
		enabled = 1
	}
	return pr60x.SQMProfile{
		WANIdx:       m.WANIndex.ValueInt64(),
		Enabled:      enabled,
		Download:     m.Download.ValueInt64(),
		DownloadUnit: m.DownloadUnit.ValueString(),
		Upload:       m.Upload.ValueInt64(),
		UploadUnit:   m.UploadUnit.ValueString(),
	}
}

func applySQM(dst *sqmModel, src *pr60x.SQMProfile) {
	dst.WANIndex = types.Int64Value(src.WANIdx)
	dst.Enabled = types.BoolValue(src.Enabled != 0)
	dst.Download = types.Int64Value(src.Download)
	dst.DownloadUnit = types.StringValue(src.DownloadUnit)
	dst.Upload = types.Int64Value(src.Upload)
	dst.UploadUnit = types.StringValue(src.UploadUnit)
}

func (r *sqmResource) write(plan *sqmModel, diags interface{ AddError(string, string) }) {
	if err := r.client.SetSQMProfile(plan.toAPI()); err != nil {
		diags.AddError("Could not set SQM profile",
			err.Error()+"\n\nError 3103 means the rate is out of range: the device requires "+
				"300 Kbps - 5 Gbps for both download and upload, even when disabled.")
		return
	}
	got, err := r.client.GetSQMProfile(plan.WANIndex.ValueInt64())
	if err != nil {
		diags.AddError("Could not read back SQM profile", err.Error())
		return
	}
	if got == nil {
		diags.AddError("SQM profile missing after write",
			fmt.Sprintf("No SQM profile for WAN index %d.", plan.WANIndex.ValueInt64()))
		return
	}
	applySQM(plan, got)
}

func (r *sqmResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan sqmModel
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

func (r *sqmResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sqmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetSQMProfile(state.WANIndex.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Could not read SQM profile", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	applySQM(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sqmResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan sqmModel
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

// Delete disables shaping but leaves the configured rates in place, because
// the device rejects a zero rate outright. Removing the resource therefore
// turns SQM off rather than clearing it.
func (r *sqmResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state sqmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	off := state.toAPI()
	off.Enabled = 0
	if err := r.client.SetSQMProfile(off); err != nil {
		resp.Diagnostics.AddError("Could not disable SQM", err.Error())
	}
}

func (r *sqmResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	idx, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import id",
			fmt.Sprintf("Expected a numeric WAN index, got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("wan_index"), idx)...)
}
