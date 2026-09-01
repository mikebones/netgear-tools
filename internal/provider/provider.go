package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
	"netgear-tools/internal/wax630e"
	"netgear-tools/internal/xs508tm"
)

var _ provider.Provider = &NetgearProvider{}

type NetgearProvider struct {
	version string
}

// clients is what every resource and data source receives. Each device family
// gets its own client and any of them may be nil - a configuration that only
// manages the switch should not have to invent router credentials. Resources
// check for nil and name the missing block rather than panicking.
type clients struct {
	PR60X   *pr60x.Client
	XS508TM *xs508tm.Client
	WAX630E *wax630e.Client
}

type deviceModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	Insecure types.Bool   `tfsdk:"insecure"`
}

type netgearProviderModel struct {
	PR60X   *deviceModel `tfsdk:"pr60x"`
	XS508TM *deviceModel `tfsdk:"xs508tm"`
	WAX630E *deviceModel `tfsdk:"wax630e"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NetgearProvider{version: version}
	}
}

func (p *NetgearProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "netgear"
	resp.Version = p.version
}

func deviceAttrs(what, defaultEndpoint, envPrefix string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:    true,
		Description: "Connection details for " + what + ". Omit entirely if you do not manage this device.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Base URL. Falls back to " + envPrefix + "_ENDPOINT, then " + defaultEndpoint + ".",
			},
			"username": schema.StringAttribute{
				Optional:    true,
				Description: "Admin username. Falls back to " + envPrefix + "_USERNAME, then admin.",
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Admin password. Falls back to " + envPrefix + "_PASSWORD, which is the recommended " +
					"way to supply it - these devices have no API-token concept, so this is the credential that " +
					"owns the hardware.",
			},
			"insecure": schema.BoolAttribute{
				Optional: true,
				Description: "Skip TLS verification. Defaults to true: these devices serve self-signed " +
					"certificates on private addresses.",
			},
		},
	}
}

func (p *NetgearProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages NETGEAR network hardware through each device's local management API - no NETGEAR " +
			"account, Insight subscription or cloud dependency. Each device family is configured in its own " +
			"attribute and has its own resource prefix (netgear_pr60x_*, netgear_xs508tm_*).",
		Attributes: map[string]schema.Attribute{
			"pr60x":   deviceAttrs("the PR60X router", "https://192.168.1.1", "PR60X"),
			"xs508tm": deviceAttrs("an XS-series smart switch", "http://192.168.1.223", "XS508TM"),
			"wax630e": deviceAttrs("a WAX6-series access point", "https://192.168.1.136", "WAX630E"),
		},
	}
}

func resolve(d *deviceModel, envPrefix, defaultEndpoint string) (endpoint, username, password string, insecure bool) {
	insecure = true
	if d != nil {
		endpoint, username, password = d.Endpoint.ValueString(), d.Username.ValueString(), d.Password.ValueString()
		if !d.Insecure.IsNull() {
			insecure = d.Insecure.ValueBool()
		}
	}
	endpoint = firstNonEmpty(endpoint, os.Getenv(envPrefix+"_ENDPOINT"), defaultEndpoint)
	username = firstNonEmpty(username, os.Getenv(envPrefix+"_USERNAME"), "admin")
	password = firstNonEmpty(password, os.Getenv(envPrefix+"_PASSWORD"))
	return
}

func (p *NetgearProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data netgearProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c := &clients{}

	// A device counts as configured when a password can be found for it,
	// whether from the block or the environment. Absence means "not managed
	// here" rather than an error.
	if endpoint, username, password, insecure := resolve(data.PR60X, "PR60X", "https://192.168.1.1"); password != "" {
		client, err := pr60x.NewClient(endpoint, username, password, insecure)
		if err != nil {
			resp.Diagnostics.AddError("Could not create PR60X client", err.Error())
			return
		}
		c.PR60X = client
	}

	if endpoint, username, password, insecure := resolve(data.XS508TM, "XS508TM", "http://192.168.1.223"); password != "" {
		client, err := xs508tm.NewClient(endpoint, username, password, insecure)
		if err != nil {
			resp.Diagnostics.AddError("Could not create XS508TM client", err.Error())
			return
		}
		c.XS508TM = client
	}

	if endpoint, username, password, insecure := resolve(data.WAX630E, "WAX630E", "https://192.168.1.136"); password != "" {
		client, err := wax630e.NewClient(endpoint, username, password, insecure)
		if err != nil {
			resp.Diagnostics.AddError("Could not create WAX630E client", err.Error())
			return
		}
		c.WAX630E = client
	}

	if c.PR60X == nil && c.XS508TM == nil && c.WAX630E == nil {
		resp.Diagnostics.AddError(
			"No NETGEAR device configured",
			"Supply a password for at least one device, either in its provider attribute or via "+
				"PR60X_PASSWORD / XS508TM_PASSWORD / WAX630E_PASSWORD. Sourcing these from Vault is preferred so the "+
				"credential never lands in state or version control.",
		)
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

// clientsFrom unwraps the provider data, tolerating the nil ProviderData that
// the framework passes during early validation walks.
func clientsFrom(providerData any) *clients {
	if providerData == nil {
		return nil
	}
	c, _ := providerData.(*clients)
	return c
}

func (p *NetgearProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// PR60X router
		NewServiceProfileResource,
		NewPortForwardingRuleResource,
		NewStaticRouteResource,
		NewVLANDHCPDNSResource,
		NewRemoteSyslogResource,
		NewSQMResource,
		NewUPnPResource,
		// XS-series switch
		NewSwitchIGMPSnoopingResource,
		NewSwitchSyslogServerResource,
		// WAX6-series access point
		NewAPSyslogResource,
	}
}

func (p *NetgearProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewDeviceInfoDataSource,
		NewServiceProfilesDataSource,
		NewPortForwardingRulesDataSource,
		NewVLANProfilesDataSource,
		NewDHCPLeasesDataSource,
		NewWANStatusDataSource,
	}
}
