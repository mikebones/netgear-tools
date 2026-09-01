package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &PR60XProvider{}

type PR60XProvider struct {
	version string
}

type pr60xProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	Insecure types.Bool   `tfsdk:"insecure"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &PR60XProvider{version: version}
	}
}

func (p *PR60XProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pr60x"
	resp.Version = p.version
}

func (p *PR60XProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a NETGEAR PR60X router through its local JSON-RPC management API. " +
			"Requires the router to be in local management mode - check with the pr60x_device_info data source.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				Description: "Base URL of the router, e.g. https://192.168.1.1. " +
					"Defaults to the PR60X_ENDPOINT environment variable, then https://192.168.1.1.",
			},
			"username": schema.StringAttribute{
				Optional: true,
				Description: "Admin username. The device's web UI only ever sends \"admin\", which is the default here. " +
					"Falls back to the PR60X_USERNAME environment variable.",
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Admin password. Falls back to the PR60X_PASSWORD environment variable, which is the " +
					"recommended way to supply it - this is the only credential the device has and it owns the network edge.",
			},
			"insecure": schema.BoolAttribute{
				Optional: true,
				Description: "Skip TLS certificate verification. Defaults to true: the router serves a self-signed " +
					"certificate for its LAN address and there is no practical way to pin a real one on a private IP.",
			},
		},
	}
}

func (p *PR60XProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data pr60xProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := firstNonEmpty(data.Endpoint.ValueString(), os.Getenv("PR60X_ENDPOINT"), "https://192.168.1.1")
	username := firstNonEmpty(data.Username.ValueString(), os.Getenv("PR60X_USERNAME"), "admin")
	password := firstNonEmpty(data.Password.ValueString(), os.Getenv("PR60X_PASSWORD"))

	if password == "" {
		resp.Diagnostics.AddError(
			"Missing PR60X admin password",
			"Set the provider's password attribute or the PR60X_PASSWORD environment variable. "+
				"PR60X_PASSWORD is preferred so the credential never lands in state or version control.",
		)
		return
	}

	insecure := true
	if !data.Insecure.IsNull() {
		insecure = data.Insecure.ValueBool()
	}

	c, err := newClient(endpoint, username, password, insecure)
	if err != nil {
		resp.Diagnostics.AddError("Could not create PR60X client", err.Error())
		return
	}

	resp.ResourceData = c
	resp.DataSourceData = c
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (p *PR60XProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewServiceProfileResource,
		NewPortForwardingRuleResource,
		NewStaticRouteResource,
		NewVLANDHCPDNSResource,
	}
}

func (p *PR60XProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewDeviceInfoDataSource,
		NewServiceProfilesDataSource,
		NewPortForwardingRulesDataSource,
		NewVLANProfilesDataSource,
		NewDHCPLeasesDataSource,
		NewWANStatusDataSource,
	}
}
