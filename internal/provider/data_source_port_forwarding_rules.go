package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &portForwardingRulesDataSource{}

type portForwardingRulesDataSource struct {
	client *client
}

func NewPortForwardingRulesDataSource() datasource.DataSource {
	return &portForwardingRulesDataSource{}
}

type portForwardingRuleModel struct {
	ID                types.Int64  `tfsdk:"id"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	ExternalService   types.String `tfsdk:"external_service"`
	InternalService   types.String `tfsdk:"internal_service"`
	DestIPAddress     types.String `tfsdk:"dest_ip_address"`
	SrcIPAddress      types.String `tfsdk:"src_ip_address"`
	WANInputInterface types.String `tfsdk:"wan_input_interface"`
	WANIPAddress      types.String `tfsdk:"wan_ip_address"`
}

type portForwardingRulesModel struct {
	Rules []portForwardingRuleModel `tfsdk:"rules"`
}

func (d *portForwardingRulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_port_forwarding_rules"
}

func (d *portForwardingRulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Every WAN-to-LAN port-forwarding rule on the router. Useful on its own as an audit of what " +
			"is actually exposed to the internet, which is otherwise recorded nowhere outside the appliance.",
		Attributes: map[string]schema.Attribute{
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":      schema.Int64Attribute{Computed: true},
						"enabled": schema.BoolAttribute{Computed: true},
						"external_service": schema.StringAttribute{
							Computed:    true,
							Description: "Service profile name matched on the WAN side.",
						},
						"internal_service": schema.StringAttribute{
							Computed: true,
							Description: "Service profile name the traffic is translated to on the LAN side. " +
								"Differs from external_service when the rule does port translation.",
						},
						"dest_ip_address":     schema.StringAttribute{Computed: true, Description: "Internal host the traffic is forwarded to."},
						"src_ip_address":      schema.StringAttribute{Computed: true, Description: "Permitted source, or \"Any\"."},
						"wan_input_interface": schema.StringAttribute{Computed: true, Description: "wan, wan1 or wan2."},
						"wan_ip_address":      schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *portForwardingRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.client = req.ProviderData.(*client)
}

func (d *portForwardingRulesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	all, err := d.client.listPortForwardingRules()
	if err != nil {
		resp.Diagnostics.AddError("Could not list port-forwarding rules", err.Error())
		return
	}

	state := portForwardingRulesModel{Rules: make([]portForwardingRuleModel, 0, len(all))}
	for _, r := range all {
		state.Rules = append(state.Rules, portForwardingRuleModel{
			ID:                types.Int64Value(r.ID),
			Enabled:           types.BoolValue(r.Enabled != 0),
			ExternalService:   types.StringValue(r.ExternalService),
			InternalService:   types.StringValue(r.InternalService),
			DestIPAddress:     types.StringValue(r.DestIPAddress),
			SrcIPAddress:      types.StringValue(r.SrcIPAddress),
			WANInputInterface: types.StringValue(r.WANInputInterface),
			WANIPAddress:      types.StringValue(r.WANIPAddress),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
