package provider

import (
	"netgear-tools/internal/pr60x"

	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &serviceProfilesDataSource{}

type serviceProfilesDataSource struct {
	client *pr60x.Client
}

func NewServiceProfilesDataSource() datasource.DataSource {
	return &serviceProfilesDataSource{}
}

type serviceProfileModel struct {
	ID        types.Int64  `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Proto     types.String `tfsdk:"proto"`
	StartPort types.Int64  `tfsdk:"start_port"`
	EndPort   types.Int64  `tfsdk:"end_port"`
	ICMPType  types.Int64  `tfsdk:"icmp_type"`
}

type serviceProfilesModel struct {
	Profiles []serviceProfileModel `tfsdk:"profiles"`
}

func (d *serviceProfilesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_service_profiles"
}

func (d *serviceProfilesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "All service profiles defined on the router, including the built-in ones. " +
			"Port-forwarding rules reference these by name.",
		Attributes: map[string]schema.Attribute{
			"profiles": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":         schema.Int64Attribute{Computed: true},
						"name":       schema.StringAttribute{Computed: true},
						"proto":      schema.StringAttribute{Computed: true, Description: "One of all, tcp, udp, icmp."},
						"start_port": schema.Int64Attribute{Computed: true, Description: "Zero for proto all and icmp."},
						"end_port":   schema.Int64Attribute{Computed: true, Description: "Zero for proto all and icmp."},
						"icmp_type":  schema.Int64Attribute{Computed: true, Description: "Only meaningful for proto icmp."},
					},
				},
			},
		},
	}
}

func (d *serviceProfilesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.client = req.ProviderData.(*pr60x.Client)
}

func (d *serviceProfilesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	all, err := d.client.ListServiceProfiles()
	if err != nil {
		resp.Diagnostics.AddError("Could not list service profiles", err.Error())
		return
	}

	state := serviceProfilesModel{Profiles: make([]serviceProfileModel, 0, len(all))}
	for _, p := range all {
		state.Profiles = append(state.Profiles, serviceProfileModel{
			ID:        types.Int64Value(p.ID),
			Name:      types.StringValue(p.Name),
			Proto:     types.StringValue(p.Proto),
			StartPort: types.Int64Value(derefInt64(p.StartPort)),
			EndPort:   types.Int64Value(derefInt64(p.EndPort)),
			ICMPType:  types.Int64Value(derefInt64(p.ICMPType)),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
