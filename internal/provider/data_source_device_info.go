package provider

import (
	"netgear-tools/internal/pr60x"

	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &deviceInfoDataSource{}

type deviceInfoDataSource struct {
	client *pr60x.Client
}

func NewDeviceInfoDataSource() datasource.DataSource {
	return &deviceInfoDataSource{}
}

type deviceInfoModel struct {
	ProductID         types.String `tfsdk:"product_id"`
	SerialNumber      types.String `tfsdk:"serial_number"`
	FirmwareVersion   types.String `tfsdk:"firmware_version"`
	BootloaderVersion types.String `tfsdk:"bootloader_version"`
	EthernetMAC       types.String `tfsdk:"ethernet_mac"`
	Region            types.String `tfsdk:"region"`
	ReleaseType       types.String `tfsdk:"release_type"`
	InsightMode       types.String `tfsdk:"insight_mode"`
	InsightStatus     types.String `tfsdk:"insight_status"`
	ManagementMode    types.String `tfsdk:"management_mode"`
	Uptime            types.String `tfsdk:"uptime"`
	FanSpeedRPM       types.Int64  `tfsdk:"fan_speed_rpm"`
	TemperatureC      types.Int64  `tfsdk:"temperature_celsius"`
}

func (d *deviceInfoDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_device_info"
}

func (d *deviceInfoDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Identity, firmware and health of the router, plus which management plane currently owns it.",
		Attributes: map[string]schema.Attribute{
			"product_id":         schema.StringAttribute{Computed: true, Description: "Model, e.g. PR60X."},
			"serial_number":      schema.StringAttribute{Computed: true},
			"firmware_version":   schema.StringAttribute{Computed: true},
			"bootloader_version": schema.StringAttribute{Computed: true},
			"ethernet_mac":       schema.StringAttribute{Computed: true},
			"region":             schema.StringAttribute{Computed: true},
			"release_type":       schema.StringAttribute{Computed: true},
			"insight_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Whether the Insight agent is enabled on the device. Independent of whether it is registered.",
			},
			"insight_status": schema.StringAttribute{
				Computed:    true,
				Description: "Insight cloud registration state, e.g. \"not registered\".",
			},
			"management_mode": schema.StringAttribute{
				Computed: true,
				Description: "\"local\" or \"insight\". If this ever reads \"insight\", the cloud becomes the source of " +
					"truth and local writes made by this provider can be reverted by NETGEAR's cloud - treat that as a " +
					"hard stop rather than something to work around.",
			},
			"uptime":              schema.StringAttribute{Computed: true, Description: "Seconds since boot, as the device reports it (a string)."},
			"fan_speed_rpm":       schema.Int64Attribute{Computed: true},
			"temperature_celsius": schema.Int64Attribute{Computed: true},
		},
	}
}

func (d *deviceInfoDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.PR60X == nil {
		resp.Diagnostics.AddError("PR60X not configured",
			"This data source reads the router. Add a `pr60x` block to the provider, or set PR60X_PASSWORD.")
		return
	}
	d.client = c.PR60X
}

func (d *deviceInfoDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	info, err := d.client.GetDeviceInfo()
	if err != nil {
		resp.Diagnostics.AddError("Could not read device info", err.Error())
		return
	}
	mode, err := d.client.GetManagementMode()
	if err != nil {
		resp.Diagnostics.AddError("Could not read management mode", err.Error())
		return
	}

	state := deviceInfoModel{
		ProductID:         types.StringValue(info.ProductID),
		SerialNumber:      types.StringValue(info.SerialNumber),
		FirmwareVersion:   types.StringValue(info.FirmwareVersion),
		BootloaderVersion: types.StringValue(info.BootloaderVersion),
		EthernetMAC:       types.StringValue(info.EthernetMAC),
		Region:            types.StringValue(info.Region),
		ReleaseType:       types.StringValue(info.ReleaseType),
		InsightMode:       types.StringValue(info.InsightMode),
		InsightStatus:     types.StringValue(info.InsightStatus),
		ManagementMode:    types.StringValue(mode.Mode),
		Uptime:            types.StringValue(info.Uptime),
		FanSpeedRPM:       types.Int64Value(info.FanSpeedRPM),
		TemperatureC:      types.Int64Value(info.SystemTemperatureCelsius),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
