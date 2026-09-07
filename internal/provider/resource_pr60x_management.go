package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &pr60xManagementResource{}
	_ resource.ResourceWithImportState = &pr60xManagementResource{}
)

type pr60xManagementResource struct {
	client *pr60x.Client
}

func NewPR60XManagementResource() resource.Resource { return &pr60xManagementResource{} }

type pr60xManagementModel struct {
	SNMPEnabled       types.Bool  `tfsdk:"snmp_enabled"`
	SNMPV1V2cEnabled  types.Bool  `tfsdk:"snmp_v1v2c_enabled"`
	SNMPV3Enabled     types.Bool  `tfsdk:"snmp_v3_enabled"`
	GUIIdleTimeoutMin types.Int64 `tfsdk:"gui_idle_timeout_minutes"`
	LEDsOff           types.Bool  `tfsdk:"leds_off"`
	MDNSReflector     types.Bool  `tfsdk:"mdns_reflector"`
	PasswordRecovery  types.Bool  `tfsdk:"password_recovery_enabled"`
	SecureDNSEnabled  types.Bool  `tfsdk:"secure_dns_enabled"`
	DefaultCommunity  types.Bool  `tfsdk:"using_default_snmp_communities"`
}

func (r *pr60xManagementResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_management"
}

func (r *pr60xManagementResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The PR60X router's management plane: SNMP, the web session timeout, LEDs, " +
			"password recovery and the mDNS reflector.\n\n" +
			"**The router ships SNMP with the community strings `public` and `private`.** SNMP is " +
			"disabled out of the box so nothing is exposed - but those are the first two strings " +
			"any scanner tries, and they are what somebody inherits the day they enable SNMP for " +
			"one metric. This resource holds it off and notices if that changes. As with the AP, " +
			"no credential attributes are modelled: `using_default_snmp_communities` reports the " +
			"state without reproducing the values or dragging them into Terraform state.\n\n" +
			"**`mdns_reflector` is the interesting one operationally.** mDNS is link-local by " +
			"design - 224.0.0.251 at TTL 1 - so it does not cross a VLAN boundary, and no amount " +
			"of IGMP snooping changes that. The reflector is the setting that makes cross-VLAN " +
			"discovery work, and it is what to reach for when a phone on one VLAN cannot see a " +
			"printer or a Chromecast on another. Off is correct while everything that needs to " +
			"discover each other shares a VLAN.\n\n" +
			"Applying this does not interrupt traffic.",
		Attributes: map[string]schema.Attribute{
			"snmp_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Master SNMP switch. False, which is the shipped state and the right one - " +
					"`pr60x-exporter` already collects this router over its own API, so SNMP would be a " +
					"second and weaker path to the same data.",
			},
			"snmp_v1v2c_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Whether the v1/v2c community path is armed. v1/v2c has no encryption and " +
					"no real authentication - the community string is a password sent in clear.",
			},
			"snmp_v3_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether SNMPv3 is armed.",
			},
			"gui_idle_timeout_minutes": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "Web UI idle timeout in minutes. **Ships at 45**, which is long for an " +
					"admin session on the device that routes the whole network. Lowering it is cheap; " +
					"the cost is retyping a password.",
			},
			"leds_off": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "True turns the front-panel LEDs off. Cosmetic, but declared because it is " +
					"the kind of setting that gets toggled once and then puzzled over later - dark LEDs " +
					"look exactly like a dead device.",
			},
			"mdns_reflector": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Reflect mDNS between VLANs. Off from the factory. See the resource " +
					"description - this is the cross-VLAN service-discovery switch.",
			},
			"password_recovery_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Security-question password reset. Off from the factory and better left " +
					"off: it adds a second path to admin guarded by answers that are typically " +
					"discoverable rather than secret.",
			},
			"secure_dns_enabled": schema.BoolAttribute{
				Computed: true,
				Description: "Read-only. DNS-over-TLS/HTTPS on the router. Off, and worth leaving off " +
					"here: this LAN resolves through its own resolver, so enabling it would send " +
					"queries past that resolver to a third party and quietly defeat local name " +
					"resolution and any DNS-level filtering.",
			},
			"using_default_snmp_communities": schema.BoolAttribute{
				Computed: true,
				Description: "Read-only. True while the shipped `public` / `private` community strings " +
					"are still in place. Harmless while SNMP is disabled, and the first thing to fix if " +
					"it is ever enabled.",
			},
		},
	}
}

func (r *pr60xManagementResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

type pr60xMgmtState struct {
	snmp   pr60x.SNMPSettings
	idle   pr60x.GUIIdleTimeout
	led    pr60x.LEDControl
	mdns   pr60x.MDNSSettings
	recov  pr60x.PasswordRecovery
	secure *pr60x.SecureDNSSettings
}

func (r *pr60xManagementResource) read() (pr60xMgmtState, error) {
	var s pr60xMgmtState
	var err error
	if s.snmp, err = r.client.GetSNMPSettings(); err != nil {
		return s, err
	}
	if s.idle, err = r.client.GetGUIIdleTimeout(); err != nil {
		return s, err
	}
	if s.led, err = r.client.GetLEDControl(); err != nil {
		return s, err
	}
	if s.mdns, err = r.client.GetMDNSSettings(); err != nil {
		return s, err
	}
	if s.recov, err = r.client.GetPasswordRecovery(); err != nil {
		return s, err
	}
	s.secure, err = r.client.GetSecureDNSSettings()
	return s, err
}

func i2b(i int) types.Bool { return types.BoolValue(i == 1) }

func b2i(b types.Bool) int {
	if b.ValueBool() {
		return 1
	}
	return 0
}

func (m *pr60xManagementModel) fromWire(s pr60xMgmtState) {
	m.SNMPEnabled = i2b(s.snmp.Enabled)
	m.SNMPV1V2cEnabled = i2b(s.snmp.V1V2cEnabled)
	m.SNMPV3Enabled = i2b(s.snmp.V3Enabled)
	m.GUIIdleTimeoutMin = types.Int64Value(int64(s.idle.Minutes))
	m.LEDsOff = i2b(s.led.LEDControl)
	m.MDNSReflector = i2b(s.mdns.EnableReflector)
	m.PasswordRecovery = i2b(s.recov.Enabled)
	// The router may answer with no secure-DNS object at all; absent reads as
	// disabled, which is both true and the safe direction.
	m.SecureDNSEnabled = types.BoolValue(s.secure != nil && s.secure.Enabled == 1)
	m.DefaultCommunity = types.BoolValue(s.snmp.UsingDefaultCommunities())
}

// apply read-modify-writes each setting, and writes only what changed.
//
// Writing only differences is not an optimisation here. Each of these is a
// separate RPC on a router that is forwarding live traffic, and several of
// them - SNMP especially - restart a daemon when written. Sending a write that
// changes nothing still pays that cost, so it is skipped.
//
// password_recovery and secure_dns are deliberately read-only: enabling either
// needs values this resource does not model (security answers, resolver
// addresses), and a resource that could turn them on without them would create
// a half-configured security control.
func (r *pr60xManagementResource) apply(plan *pr60xManagementModel, diags diagSink) {
	cur, err := r.read()
	if err != nil {
		diags.AddError("Could not read the router's management settings", err.Error())
		return
	}

	wantSNMP := cur.snmp
	wantSNMP.Enabled = b2i(plan.SNMPEnabled)
	if v := plan.SNMPV1V2cEnabled; !v.IsNull() && !v.IsUnknown() {
		wantSNMP.V1V2cEnabled = b2i(v)
	}
	if v := plan.SNMPV3Enabled; !v.IsNull() && !v.IsUnknown() {
		wantSNMP.V3Enabled = b2i(v)
	}
	// Compared field by field rather than with ==: SNMPSettings carries a
	// json.RawMessage for the v3 block, which makes the struct incomparable.
	// Only the switches this resource owns are checked, which is also what
	// keeps an untouched v3 blob from looking like a change every plan.
	snmpChanged := wantSNMP.Enabled != cur.snmp.Enabled ||
		wantSNMP.V1V2cEnabled != cur.snmp.V1V2cEnabled ||
		wantSNMP.V3Enabled != cur.snmp.V3Enabled
	if snmpChanged {
		if err := r.client.SetSNMPSettings(wantSNMP); err != nil {
			diags.AddError("Could not write the SNMP settings", err.Error())
			return
		}
	}

	if v := plan.GUIIdleTimeoutMin; !v.IsNull() && !v.IsUnknown() && int(v.ValueInt64()) != cur.idle.Minutes {
		if err := r.client.SetGUIIdleTimeout(pr60x.GUIIdleTimeout{Minutes: int(v.ValueInt64())}); err != nil {
			diags.AddError("Could not write the GUI idle timeout", err.Error())
			return
		}
	}
	if v := plan.LEDsOff; !v.IsNull() && !v.IsUnknown() && b2i(v) != cur.led.LEDControl {
		if err := r.client.SetLEDControl(pr60x.LEDControl{LEDControl: b2i(v)}); err != nil {
			diags.AddError("Could not write the LED setting", err.Error())
			return
		}
	}
	if v := plan.MDNSReflector; !v.IsNull() && !v.IsUnknown() && b2i(v) != cur.mdns.EnableReflector {
		if err := r.client.SetMDNSSettings(pr60x.MDNSSettings{EnableReflector: b2i(v)}); err != nil {
			diags.AddError("Could not write the mDNS reflector setting", err.Error())
			return
		}
	}

	got, err := r.read()
	if err != nil {
		diags.AddError("Could not read back the router's management settings", err.Error())
		return
	}
	plan.fromWire(got)
}

func (r *pr60xManagementResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pr60xManagementModel
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

func (r *pr60xManagementResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pr60xManagementModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the router's management settings", err.Error())
		return
	}
	state.fromWire(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pr60xManagementResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pr60xManagementModel
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

// Delete disables SNMP and does nothing else.
//
// This resource exists mainly to hold SNMP off, and leaving an SNMP service
// running that nobody tracks is the failure mode worth preventing. The other
// settings are left alone: restoring factory values for LEDs, the idle timeout
// or the mDNS reflector on destroy would change live behaviour as a side
// effect of a config cleanup.
func (r *pr60xManagementResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	cur, err := r.client.GetSNMPSettings()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the SNMP settings before disabling", err.Error())
		return
	}
	if cur.Enabled == 0 {
		return
	}
	cur.Enabled = 0
	if err := r.client.SetSNMPSettings(cur); err != nil {
		resp.Diagnostics.AddError("Could not disable SNMP", err.Error())
	}
}

// ImportState takes any ID - the router has one management plane:
//
//	terraform import netgear_pr60x_management.this management
func (r *pr60xManagementResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the router's management settings", err.Error())
		return
	}
	var state pr60xManagementModel
	state.fromWire(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
