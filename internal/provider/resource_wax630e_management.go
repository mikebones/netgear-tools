package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/wax630e"
)

var (
	_ resource.Resource                = &wax630eManagementResource{}
	_ resource.ResourceWithImportState = &wax630eManagementResource{}
)

type wax630eManagementResource struct {
	client *wax630e.Client
}

func NewWAX630EManagementResource() resource.Resource { return &wax630eManagementResource{} }

type wax630eManagementModel struct {
	CloudManagement   types.Bool   `tfsdk:"cloud_management"`
	SpanningTree      types.Bool   `tfsdk:"spanning_tree"`
	SSHEnabled        types.Bool   `tfsdk:"ssh_enabled"`
	TelnetEnabled     types.Bool   `tfsdk:"telnet_enabled"`
	SessionTimeoutSec types.Int64  `tfsdk:"session_timeout_seconds"`
	APName            types.String `tfsdk:"ap_name"`
	DayZeroPending    types.Bool   `tfsdk:"day_zero_pending"`
}

func (r *wax630eManagementResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_management"
}

func (r *wax630eManagementResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The WAX630E's management plane: cloud management, spanning tree, remote shells " +
			"and the session idle timeout.\n\n" +
			"**This is the resource that matters most if the AP is ever reset or replaced.** Taken " +
			"from the firmware's own `/etc/default-config`, a factory device comes up with " +
			"`cloudStatus 1` - NETGEAR Insight **cloud management enabled** - and the day-zero " +
			"wizard armed. Nothing warns you: the AP simply starts trying to reach a vendor cloud " +
			"service it was deliberately kept away from. Everything else on this AP can be wrong " +
			"and merely mean worse wifi; this one changes who administers the device.\n\n" +
			"Unlike the radio and SSID resources, **applying this does not interrupt anything** - " +
			"no radio bounces and no client disconnects - so it is safe to apply rather than only " +
			"import.",
		Attributes: map[string]schema.Attribute{
			"cloud_management": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "NETGEAR Insight cloud management. **Defaults to false here and ships as " +
					"TRUE from the factory.** False keeps the AP locally managed, which is what every " +
					"other resource in this configuration assumes - a cloud-managed AP takes its " +
					"configuration from NETGEAR, not from Terraform.",
			},
			"spanning_tree": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "The AP's own STP participation.\n\n" +
					"**Not cosmetic on this network.** A WAX630E on firmware older than 11.8.0.9 emits " +
					"STP frames with an incorrect Forward Delay that crashes the switch it plugs into, " +
					"and that switch supplies PoE to the whole cluster. The switch side is defended " +
					"independently by `netgear_ms510txup_stp_port`, which is the stronger fix because " +
					"it does not depend on the AP behaving. This is the other half, and the AP is an " +
					"edge device with one uplink, so it has nothing to contribute to spanning tree " +
					"anyway.",
			},
			"ssh_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Remote SSH access to the AP. Off from the factory and nothing here needs " +
					"a shell on it.",
			},
			"telnet_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Remote Telnet access. Off from the factory. Telnet is plaintext, " +
					"including the admin password.",
			},
			"session_timeout_seconds": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "Web session idle timeout, in seconds. `300` is the factory value.\n\n" +
					"Worth understanding rather than tuning blindly: the AP caps concurrent logins and " +
					"frees a slot only after a session has been idle this long. Any tool that exits " +
					"without logging out burns a slot for the full duration, and once the slots are " +
					"gone every login is refused - including the one you would need to raise this " +
					"value or reboot the device. RAISING THIS MAKES THAT FAILURE MODE WORSE.",
			},
			"ap_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "The AP's device name. This is what identifies it in syslog and in the " +
					"exporter's info metric, so a reset back to the factory `NETGEARXXXXXX` pattern " +
					"quietly breaks log attribution.",
			},
			"day_zero_pending": schema.BoolAttribute{
				Computed: true,
				Description: "Read-only. True while the out-of-box provisioning wizard is still armed, " +
					"which on a configured AP means it has been factory reset.",
			},
		},
	}
}

func (r *wax630eManagementResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.WAX630E == nil {
		resp.Diagnostics.AddError("WAX630E not configured",
			"This resource manages the access point. Add a `wax630e` block to the provider, or set WAX630E_PASSWORD.")
		return
	}
	r.client = c.WAX630E
}

func (m *wax630eManagementModel) fromWire(b wax630e.ManagementSettings, ra wax630e.RemoteAccess) {
	m.CloudManagement = wireBool(b.CloudStatus)
	m.SpanningTree = wireBool(b.SpanTreeStatus)
	m.DayZeroPending = wireBool(b.DayZeroStatus)
	m.APName = types.StringValue(b.APName)
	m.SSHEnabled = wireBool(ra.SSHStatus)
	m.TelnetEnabled = wireBool(ra.TelnetStatus)
	m.SessionTimeoutSec = types.Int64Value(atoi64(ra.InactivityTimeOut))
}

func (r *wax630eManagementResource) read() (wax630e.ManagementSettings, wax630e.RemoteAccess, error) {
	b, err := r.client.GetManagement()
	if err != nil {
		return b, wax630e.RemoteAccess{}, err
	}
	ra, err := r.client.GetRemoteAccess()
	return b, ra, err
}

// apply read-modify-writes both halves.
//
// They are two separate subtrees - basicSettings and remoteSettings - and each
// shares its subtree with something else this provider owns: basicSettings
// holds the AP's IP configuration (netgear_wax630e_network) and remoteSettings
// holds SNMP (netgear_wax630e_snmp). Sending only the fields modelled here
// leaves the neighbours alone, which is why neither write sends a whole
// subtree.
func (r *wax630eManagementResource) apply(plan *wax630eManagementModel, diags diagSink) {
	curB, curR, err := r.read()
	if err != nil {
		diags.AddError("Could not read the management settings", err.Error())
		return
	}

	wantB := wax630e.ManagementSettings{
		CloudStatus:    boolWire(plan.CloudManagement),
		SpanTreeStatus: boolWire(plan.SpanningTree),
	}
	if v := plan.APName; !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		wantB.APName = v.ValueString()
	} else {
		wantB.APName = curB.APName
	}
	if err := r.client.SetManagement(wantB); err != nil {
		diags.AddError("Could not write the management settings", err.Error())
		return
	}

	wantR := wax630e.RemoteAccess{
		SSHStatus:    boolWire(plan.SSHEnabled),
		TelnetStatus: boolWire(plan.TelnetEnabled),
	}
	if v := plan.SessionTimeoutSec; !v.IsNull() && !v.IsUnknown() {
		wantR.InactivityTimeOut = i2s(v.ValueInt64())
	} else {
		wantR.InactivityTimeOut = curR.InactivityTimeOut
	}
	if err := r.client.SetRemoteAccess(wantR); err != nil {
		diags.AddError("Could not write the remote access settings", err.Error())
		return
	}

	gotB, gotR, err := r.read()
	if err != nil {
		diags.AddError("Could not read back the management settings", err.Error())
		return
	}
	plan.fromWire(gotB, gotR)
}

func (r *wax630eManagementResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan wax630eManagementModel
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

func (r *wax630eManagementResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state wax630eManagementModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	b, ra, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the management settings", err.Error())
		return
	}
	state.fromWire(b, ra)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *wax630eManagementResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan wax630eManagementModel
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

// Delete DOES NOTHING TO THE DEVICE, deliberately.
//
// The tidy inverse would be restoring factory values, and the factory value
// for cloud_management is ENABLED - so destroying this resource would hand the
// AP to NETGEAR's cloud as a side effect of removing it from a config file.
// That is the opposite of what anyone means. Removing the resource stops
// Terraform tracking the management plane; the settings stay as they are.
func (r *wax630eManagementResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes any ID - there is one management plane:
//
//	terraform import netgear_wax630e_management.this management
func (r *wax630eManagementResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	b, ra, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the management settings", err.Error())
		return
	}
	var state wax630eManagementModel
	state.fromWire(b, ra)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
