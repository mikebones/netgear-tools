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
	_ resource.Resource                = &wax630eSNMPResource{}
	_ resource.ResourceWithImportState = &wax630eSNMPResource{}
)

type wax630eSNMPResource struct {
	client *wax630e.Client
}

func NewWAX630ESNMPResource() resource.Resource { return &wax630eSNMPResource{} }

type wax630eSNMPModel struct {
	Enabled      types.Bool   `tfsdk:"enabled"`
	V1V2cEnabled types.Bool   `tfsdk:"v1v2c_enabled"`
	V3Enabled    types.Bool   `tfsdk:"v3_enabled"`
	TrapServerIP types.String `tfsdk:"trap_server_ip"`
	TrapPort     types.String `tfsdk:"trap_port"`
	V3UserName   types.String `tfsdk:"v3_username"`
	V3AuthProto  types.String `tfsdk:"v3_auth_protocol"`
	V3PrivProto  types.String `tfsdk:"v3_priv_protocol"`
	UsingDefault types.Bool   `tfsdk:"using_default_credentials"`
}

func (r *wax630eSNMPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_snmp"
}

func (r *wax630eSNMPResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "SNMP on the WAX630E. **SNMPv1/v2c is new in firmware 12.8.0.6** - earlier " +
			"releases offer v3 only, and this whole subtree does not exist on an AP that has not " +
			"been upgraded.\n\n" +
			"**This resource exists to keep SNMP OFF and to notice if that changes.** The AP ships " +
			"it disabled but fully pre-populated: read community `snmpv1v2cuser`, trap community " +
			"`trapuser`, v3 auth and privacy passphrases both literally `snmp1234` under MD5 and " +
			"DES, and a trap target already pointing at the gateway. None of that is reachable " +
			"while `enabled` is false. It is, however, exactly what somebody gets the day they " +
			"turn SNMP on to collect one metric - and they will not think to change credentials " +
			"they never chose.\n\n" +
			"**No credential attributes here, on purpose.** Community strings and passphrases are " +
			"secrets, and a Terraform resource that accepted them would put them in plan output " +
			"and in state. `using_default_credentials` reports whether the shipped values are " +
			"still in place without reproducing them; set real ones out of band, from Vault, if " +
			"SNMP is ever genuinely wanted.\n\n" +
			"This cluster already collects the AP's state over its HTTP API via `wax630e-exporter`, " +
			"so SNMP would be a second, weaker path to the same data. The reason to model it is " +
			"drift, not monitoring.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Master SNMP switch. Defaults to false, which is both the shipped state and " +
					"the right one here - turning it on exposes the pre-populated credentials described above.",
			},
			"v1v2c_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Whether the v1/v2c community path is armed. **Note this ships as `true`** " +
					"even though the master switch is off, so it takes effect the moment SNMP is enabled. " +
					"v1/v2c has no encryption and no real authentication - the community string is a " +
					"password sent in clear.",
			},
			"v3_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether SNMPv3 is armed. Ships false.",
			},
			"trap_server_ip": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Where traps are sent. Ships pointing at the gateway, which is not a trap " +
					"receiver - so traps would go nowhere even if enabled.",
			},
			"trap_port": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Trap destination port. `162` is the standard.",
			},
			"v3_username": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "SNMPv3 polling username. Not a secret; the passphrases are, and are not modelled.",
			},
			"v3_auth_protocol": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "v3 authentication digest, `MD5` or `SHA`. **Ships as `MD5`**, which is " +
					"broken - if v3 is ever actually used, this wants to be `SHA`.",
			},
			"v3_priv_protocol": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "v3 privacy cipher, `DES` or `AES`. **Ships as `DES`**, which is a 56-bit " +
					"cipher and should be `AES` if v3 is ever used.",
			},
			"using_default_credentials": schema.BoolAttribute{
				Computed: true,
				Description: "Read-only. True while any of the factory community strings or the `snmp1234` " +
					"passphrases are still in place. Harmless while SNMP is disabled, and the first thing " +
					"to fix if it is ever enabled.",
			},
		},
	}
}

func (r *wax630eSNMPResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// shippedCredential reports whether a value is one of the factory defaults.
// Listed explicitly rather than pattern-matched: the point is to name the
// exact values this hardware ships with, so the check does not quietly stop
// working when somebody picks a password that happens to look similar.
func shippedCredential(v string) bool {
	switch v {
	case "snmpv1v2cuser", "trapuser", "snmp1234", "snmpv3user", "snmptrap":
		return true
	}
	return false
}

func (m *wax630eSNMPModel) fromWire(s wax630e.SNMPSettings) {
	m.Enabled = wireBool(s.SNMPStatus)
	m.V1V2cEnabled = wireBool(s.V1V2c.Status)
	m.V3Enabled = wireBool(s.V3.Status)
	m.TrapServerIP = types.StringValue(s.TrapTarget.TrapServerIP)
	m.TrapPort = types.StringValue(s.TrapTarget.TrapPort)
	m.V3UserName = types.StringValue(s.V3.UserName)
	m.V3AuthProto = types.StringValue(s.V3.AuthProtocol)
	m.V3PrivProto = types.StringValue(s.V3.PrivProtocol)
	m.UsingDefault = types.BoolValue(
		shippedCredential(s.V1V2c.ReadOnlyCommunity) ||
			shippedCredential(s.V1V2c.TrapCommunity) ||
			shippedCredential(s.V3.AuthPassphrase) ||
			shippedCredential(s.V3.PrivPassphrase) ||
			shippedCredential(s.V3.TrapUser.AuthPassphrase) ||
			shippedCredential(s.V3.TrapUser.PrivPassphrase))
}

// apply read-modify-writes. Reading first is what keeps the passphrases
// intact: this resource models none of them, and sending a struct with empty
// passphrase fields would either clear them or be rejected. Carrying the live
// values forward means Terraform can manage the switches without ever needing
// to know the secrets.
func (r *wax630eSNMPResource) apply(plan *wax630eSNMPModel, diags diagSink) {
	cur, err := r.client.GetSNMP()
	if err != nil {
		diags.AddError("Could not read the SNMP settings", err.Error())
		return
	}

	want := cur
	want.SNMPStatus = boolWire(plan.Enabled)
	if !plan.V1V2cEnabled.IsUnknown() && !plan.V1V2cEnabled.IsNull() {
		want.V1V2c.Status = boolWire(plan.V1V2cEnabled)
	}
	if !plan.V3Enabled.IsUnknown() && !plan.V3Enabled.IsNull() {
		want.V3.Status = boolWire(plan.V3Enabled)
	}
	if v := plan.TrapServerIP; !v.IsUnknown() && !v.IsNull() {
		want.TrapTarget.TrapServerIP = v.ValueString()
	}
	if v := plan.TrapPort; !v.IsUnknown() && !v.IsNull() {
		want.TrapTarget.TrapPort = v.ValueString()
	}
	if v := plan.V3UserName; !v.IsUnknown() && !v.IsNull() {
		want.V3.UserName = v.ValueString()
	}
	if v := plan.V3AuthProto; !v.IsUnknown() && !v.IsNull() {
		want.V3.AuthProtocol = v.ValueString()
	}
	if v := plan.V3PrivProto; !v.IsUnknown() && !v.IsNull() {
		want.V3.PrivProtocol = v.ValueString()
	}

	if err := r.client.SetSNMP(want); err != nil {
		diags.AddError("Could not write the SNMP settings", err.Error())
		return
	}
	got, err := r.client.GetSNMP()
	if err != nil {
		diags.AddError("Could not read back the SNMP settings", err.Error())
		return
	}
	plan.fromWire(got)
}

func (r *wax630eSNMPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan wax630eSNMPModel
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

func (r *wax630eSNMPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state wax630eSNMPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetSNMP()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the SNMP settings", err.Error())
		return
	}
	state.fromWire(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *wax630eSNMPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan wax630eSNMPModel
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

// Delete disables SNMP.
//
// Unlike the radio resource's no-op Delete, the safe direction here is to act:
// this resource exists to hold SNMP off, and the failure mode of doing nothing
// on destroy is leaving an SNMP service running that nobody is tracking any
// more. Disabling is also non-disruptive - no client depends on it.
func (r *wax630eSNMPResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	cur, err := r.client.GetSNMP()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the SNMP settings before disabling", err.Error())
		return
	}
	cur.SNMPStatus = "0"
	if err := r.client.SetSNMP(cur); err != nil {
		resp.Diagnostics.AddError("Could not disable SNMP", err.Error())
	}
}

// ImportState takes any ID - the AP has exactly one SNMP configuration:
//
//	terraform import netgear_wax630e_snmp.off snmp
func (r *wax630eSNMPResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetSNMP()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the SNMP settings", err.Error())
		return
	}
	var state wax630eSNMPModel
	state.fromWire(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
