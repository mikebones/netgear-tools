package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/wax630e"
)

var (
	_ resource.Resource                = &wax630eSSIDResource{}
	_ resource.ResourceWithImportState = &wax630eSSIDResource{}
)

type wax630eSSIDResource struct {
	client *wax630e.Client
}

func NewWAX630ESSIDResource() resource.Resource { return &wax630eSSIDResource{} }

type wax630eSSIDModel struct {
	Key                types.String `tfsdk:"key"`
	Name               types.String `tfsdk:"name"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	Radios             types.List   `tfsdk:"radios"`
	VLANID             types.Int64  `tfsdk:"vlan_id"`
	Hidden             types.Bool   `tfsdk:"hidden"`
	ClientSeparation   types.Bool   `tfsdk:"client_separation"`
	AuthenticationType types.Int64  `tfsdk:"authentication_type"`
	Encryption         types.Int64  `tfsdk:"encryption"`
	PMF                types.Int64  `tfsdk:"protected_management_frames"`
	PresharedKey       types.String `tfsdk:"preshared_key"`
	BandSteering       types.Bool   `tfsdk:"band_steering"`
	AllowUIAccess      types.Bool   `tfsdk:"allow_ui_access"`
	FastRoaming11r     types.Bool   `tfsdk:"fast_roaming_11r"`
	Assisted11kv       types.Bool   `tfsdk:"assisted_roaming_11kv"`
	CaptivePortal      types.Bool   `tfsdk:"captive_portal"`
	URLTracking        types.Bool   `tfsdk:"url_tracking"`
	Band               types.String `tfsdk:"band"`
}

func (r *wax630eSSIDResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_ssid"
}

func (r *wax630eSSIDResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One SSID on the WAX630E, across the radios that carry it.\n\n" +
			"**EVERY APPLY BOUNCES THE SSID.** The AP restarts the virtual AP when this is " +
			"written, so clients disassociate and reconnect - and it does that even when the " +
			"values written are identical to the ones already there. There is no free no-op " +
			"apply here. Plan before you apply and mean it.\n\n" +
			"**Why this exists: the AP can be factory-reset by its own upgrade flow.** Climbing " +
			"this device from 10.8.x to 12.8.0.6 offered exactly that twice, and a reset takes " +
			"every SSID and passphrase with it. This resource is the declarative half of the " +
			"answer; `netgear_wax630e_config_backup` is the other half and captures the settings " +
			"no resource here models.\n\n" +
			"**Settings are applied identically to every radio in `radios`.** The device stores " +
			"them per radio and would let them diverge; this resource deliberately will not, " +
			"because an SSID whose passphrase differs by band is a support call, not a feature. " +
			"Anything this resource does not model is carried through from the device untouched " +
			"on every write, so a firmware-specific field cannot be cleared by applying.\n\n" +
			"**Numeric codes are passed through as the device's own numbers.** " +
			"`authentication_type`, `encryption` and `protected_management_frames` are opaque " +
			"integers with no documentation the device exposes. Import first and read what is " +
			"there rather than guessing - the AP accepts an out-of-range value and silently " +
			"produces a network nothing can join.",
		Attributes: map[string]schema.Attribute{
			"key": schema.StringAttribute{
				Required: true,
				Description: "The AP's own slot name for this SSID: `SSID1`, `SSID2`, and so on. Not the " +
					"network name - see `name`. These are the keys `ssidGetDetails` returns, and they are " +
					"positional, so an SSID's key does not follow it if the list is reordered in the web UI.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The broadcast network name.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the SSID is broadcast at all. **False takes the network off the air.**",
			},
			"radios": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Radios carrying this SSID: `wlan0` (2.4 GHz), `wlan1` (5 GHz), `wlan2` " +
					"(6 GHz). Order does not matter. Dropping a radio from the list does NOT remove the " +
					"SSID from it - the AP has no such operation in this call - so removing a band is a " +
					"web UI job.",
			},
			"vlan_id": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "VLAN this SSID's traffic lands on. `1` is the untagged LAN here. Check the " +
					"switch actually carries the VLAN to the AP's port before changing this, or the " +
					"network will associate and then have no path anywhere.",
			},
			"hidden": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Suppress the SSID from beacons. Worth knowing this is not a security " +
					"control - the name is still in every association, and it mostly makes client " +
					"roaming worse.",
			},
			"client_separation": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Stop clients on this SSID reaching each other. Right for a guest network, " +
					"wrong for one where devices need to see each other - it breaks casting and printer " +
					"discovery.",
			},
			"authentication_type": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "The device's numeric authentication code. `80` is what this AP's WPA2/WPA3 " +
					"personal networks use. The client only sends `preshared_key` for the codes that take " +
					"one - 32, 48, 80 and 96 - matching the AP's own UI logic.",
			},
			"encryption": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The device's numeric cipher code.",
			},
			"protected_management_frames": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "802.11w PMF: typically `0` disabled, `1` capable, `2` required. WPA3 " +
					"requires it. Forcing `2` will lock out older clients that cannot do PMF at all.",
			},
			"preshared_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "The passphrase. **Optional, and leaving it unset is a supported choice** - " +
					"the current value is then read from the AP and written straight back, so Terraform " +
					"manages everything else about the SSID without the secret ever entering state.\n\n" +
					"Set it only from a secret store, never a literal. Terraform state holds this in " +
					"clear, so a hardcoded passphrase here is a passphrase in whatever holds the state " +
					"file. If you want the passphrase recoverable after a factory reset, the config " +
					"backup is the better place for it.",
			},
			"band_steering": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Nudge dual-band clients onto 5 GHz. Helps when a client would otherwise " +
					"cling to 2.4 GHz; can cause reconnect loops with clients that disagree.",
			},
			"allow_ui_access": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Whether clients on this SSID can reach the AP's own management interface. " +
					"Should be false on any guest network.",
			},
			"fast_roaming_11r": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "802.11r fast transition. Only meaningful with more than one AP, and some " +
					"older clients handle it badly.",
			},
			"assisted_roaming_11kv": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "802.11k/v assisted roaming. Same caveat as `fast_roaming_11r`.",
			},
			"captive_portal": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the captive portal is armed on this SSID.",
			},
			"url_tracking": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Log the URLs clients visit. Off, and worth leaving off - it is traffic " +
					"surveillance of everyone on the network.",
			},
			"band": schema.StringAttribute{
				Computed: true,
				Description: "Read-only. The device's own summary of which bands carry this SSID, e.g. " +
					"`all`. Derived from the radio map rather than set independently.",
			},
		},
	}
}

func (r *wax630eSSIDResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// authTypesTakingPSK are the authenticationType codes that carry a preshared
// key. Taken from the AP's own UI, which gates sending presharedKey on exactly
// this set; sending one for any other code is at best ignored.
var authTypesTakingPSK = map[int64]bool{32: true, 48: true, 80: true, 96: true}

// pump forwards framework diagnostics into a diagSink, which carries only
// AddError/AddWarning. Returns true if anything was an error, so callers can
// bail in one line.
func pump(d diag.Diagnostics, into diagSink) bool {
	for _, x := range d {
		if x.Severity() == diag.SeverityError {
			into.AddError(x.Summary(), x.Detail())
		} else {
			into.AddWarning(x.Summary(), x.Detail())
		}
	}
	return d.HasError()
}

// ssidEntry is one SSID as read back: the radio map plus the derived band.
type ssidEntry struct {
	band   string
	radios map[string]map[string]any // radio -> vap -> settings
}

// readSSID pulls one SSID out of the full details blob.
//
// The blob is deliberately untyped all the way through - see GetSSIDDetails -
// so this walks it defensively rather than trusting a shape. A missing key
// returns ok=false so callers can treat it as "gone" rather than erroring.
func readSSID(all wax630e.SSIDDetails, key string) (ssidEntry, bool) {
	raw, ok := all[key]
	if !ok {
		return ssidEntry{}, false
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return ssidEntry{}, false
	}
	e := ssidEntry{radios: map[string]map[string]any{}}
	for k, v := range obj {
		if k == "band" {
			if s, ok := v.(string); ok {
				e.band = s
			}
			continue
		}
		if !strings.HasPrefix(k, "wlan") {
			continue
		}
		vaps, ok := v.(map[string]any)
		if !ok {
			continue
		}
		inner := map[string]any{}
		for vap, sv := range vaps {
			if sm, ok := sv.(map[string]any); ok {
				inner[vap] = sm
			}
		}
		if len(inner) > 0 {
			e.radios[k] = inner
		}
	}
	return e, len(e.radios) > 0
}

// firstVAP returns the settings map for any one radio, which is what the
// Terraform model is populated from. The resource keeps every radio identical,
// so any of them describes all of them.
func (e ssidEntry) firstVAP() map[string]any {
	names := make([]string, 0, len(e.radios))
	for k := range e.radios {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, v := range e.radios[n] {
			if m, ok := v.(map[string]any); ok {
				return m
			}
		}
	}
	return nil
}

// num reads a field that the AP may send as a JSON number or as a string.
// Both appear in the same blob depending on the field, so neither assumption
// is safe on its own.
func num(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	}
	return 0
}

func flag(m map[string]any, k string) types.Bool { return types.BoolValue(num(m, k) == 1) }

func str(m map[string]any, k string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

func (m *wax630eSSIDModel) fromWire(ctx context.Context, key string, e ssidEntry, diags diagSink) {
	v := e.firstVAP()
	if v == nil {
		diags.AddError("The AP returned no settings for this SSID",
			"Slot "+key+" has no radio entries, which should not happen for an SSID that exists.")
		return
	}
	m.Key = types.StringValue(key)
	m.Name = types.StringValue(str(v, "ssid"))
	m.Enabled = flag(v, "vapProfileStatus")
	m.VLANID = types.Int64Value(num(v, "vlanID"))
	m.Hidden = flag(v, "hideNetworkName")
	m.ClientSeparation = flag(v, "clientSeparation")
	m.AuthenticationType = types.Int64Value(num(v, "authenticationType"))
	m.Encryption = types.Int64Value(num(v, "encryption"))
	m.PMF = types.Int64Value(num(v, "ieee80211w"))
	m.BandSteering = flag(v, "bandSteeringStatus")
	m.AllowUIAccess = flag(v, "allowUIAccess")
	m.FastRoaming11r = flag(v, "11rStatus")
	m.Assisted11kv = flag(v, "11kvStatus")
	m.CaptivePortal = flag(v, "cpStatus")
	m.URLTracking = flag(v, "urlTracking")
	m.Band = types.StringValue(e.band)

	radios := make([]string, 0, len(e.radios))
	for k := range e.radios {
		radios = append(radios, k)
	}
	sort.Strings(radios)
	list, d := types.ListValueFrom(ctx, types.StringType, radios)
	pump(d, diags)
	m.Radios = list
	// preshared_key is intentionally NOT populated from the device. Reading it
	// back would move the passphrase into state for every configuration,
	// including the ones that deliberately never set it.
}

func i2s(v int64) string { return strconv.FormatInt(v, 10) }

func b2s(b types.Bool) any {
	if b.ValueBool() {
		return float64(1)
	}
	return float64(0)
}

// apply read-modify-writes the SSID across every radio in the plan.
func (r *wax630eSSIDResource) apply(ctx context.Context, plan *wax630eSSIDModel, diags diagSink) {
	key := plan.Key.ValueString()

	all, err := r.client.GetSSIDDetails()
	if err != nil {
		diags.AddError("Could not read the SSIDs", err.Error())
		return
	}
	cur, ok := readSSID(all, key)
	if !ok {
		diags.AddError("No such SSID slot",
			fmt.Sprintf("The AP has no SSID slot %q. This resource configures an existing slot; "+
				"it cannot create one, because the AP has no API for adding an SSID. Create it in "+
				"the web UI first, then import it.", key))
		return
	}

	var wantRadios []string
	if pump(plan.Radios.ElementsAs(ctx, &wantRadios, false), diags) {
		return
	}

	out := map[string]any{}
	for _, radio := range wantRadios {
		vaps, ok := cur.radios[radio]
		if !ok {
			diags.AddError("That radio does not carry this SSID",
				fmt.Sprintf("Slot %s is not present on %s. This call can change an SSID on the radios "+
					"that already carry it, but it cannot add it to a new band - do that in the web UI "+
					"first, then apply.", key, radio))
			return
		}
		vapOut := map[string]any{}
		for vap, raw := range vaps {
			settings, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			// Copy the live settings and change only what is modelled, so a
			// field this provider does not know about survives the write.
			next := make(map[string]any, len(settings))
			for k, v := range settings {
				next[k] = v
			}
			next["ssid"] = plan.Name.ValueString()
			next["vapProfileStatus"] = b2s(plan.Enabled)
			next["vlanID"] = float64(plan.VLANID.ValueInt64())
			next["hideNetworkName"] = b2s(plan.Hidden)
			next["clientSeparation"] = b2s(plan.ClientSeparation)
			next["authenticationType"] = float64(plan.AuthenticationType.ValueInt64())
			next["encryption"] = float64(plan.Encryption.ValueInt64())
			next["ieee80211w"] = float64(plan.PMF.ValueInt64())
			next["bandSteeringStatus"] = b2s(plan.BandSteering)
			next["allowUIAccess"] = b2s(plan.AllowUIAccess)
			next["11rStatus"] = b2s(plan.FastRoaming11r)
			next["11kvStatus"] = b2s(plan.Assisted11kv)
			next["cpStatus"] = b2s(plan.CaptivePortal)
			next["urlTracking"] = b2s(plan.URLTracking)

			// Only touch the passphrase when the configuration actually
			// supplies one. Unset means "keep what the AP has", which is what
			// lets this resource manage an SSID without holding its secret.
			if v := plan.PresharedKey; !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
				if !authTypesTakingPSK[plan.AuthenticationType.ValueInt64()] {
					diags.AddError("This authentication type does not take a preshared key",
						fmt.Sprintf("authentication_type %s is not one of the codes that carry a "+
							"passphrase (32, 48, 80, 96), so preshared_key would be ignored. Remove it, "+
							"or set an authentication type that uses one.",
							i2s(plan.AuthenticationType.ValueInt64())))
					return
				}
				next["presharedKey"] = v.ValueString()
			}
			vapOut[vap] = next
		}
		out[radio] = vapOut
	}

	if err := r.client.SetSSIDDetails(key, out); err != nil {
		diags.AddError("Could not write the SSID", err.Error())
		return
	}

	all, err = r.client.GetSSIDDetails()
	if err != nil {
		diags.AddError("Could not read back the SSID", err.Error())
		return
	}
	got, ok := readSSID(all, key)
	if !ok {
		diags.AddError("The SSID disappeared after writing it",
			"Slot "+key+" is no longer present. Check the AP's web UI before applying again.")
		return
	}
	psk := plan.PresharedKey
	plan.fromWire(ctx, key, got, diags)
	plan.PresharedKey = psk
}

func (r *wax630eSSIDResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan wax630eSSIDModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *wax630eSSIDResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state wax630eSSIDModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	all, err := r.client.GetSSIDDetails()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the SSIDs", err.Error())
		return
	}
	got, ok := readSSID(all, state.Key.ValueString())
	if !ok {
		resp.State.RemoveResource(ctx)
		return
	}
	psk := state.PresharedKey
	state.fromWire(ctx, state.Key.ValueString(), got, &resp.Diagnostics)
	state.PresharedKey = psk
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *wax630eSSIDResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan wax630eSSIDModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete DOES NOTHING TO THE DEVICE, deliberately.
//
// The AP has no API for removing an SSID, only for configuring the slots it
// already has. The nearest thing available - setting vapProfileStatus to 0 -
// would take a live wireless network off the air because a resource was
// removed from a config file, which is a much larger consequence than the
// action implies. Removing the resource stops Terraform tracking the SSID; the
// SSID keeps broadcasting. Disable it explicitly with `enabled = false` if
// that is what you want.
func (r *wax630eSSIDResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes the AP's slot key:
//
//	terraform import netgear_wax630e_ssid.main SSID1
func (r *wax630eSSIDResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	key := strings.TrimSpace(req.ID)
	all, err := r.client.GetSSIDDetails()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the SSIDs", err.Error())
		return
	}
	got, ok := readSSID(all, key)
	if !ok {
		keys := make([]string, 0, len(all))
		for k := range all {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		resp.Diagnostics.AddError("No such SSID slot",
			fmt.Sprintf("The AP has no SSID slot %q. Slots present: %s. Import with the slot key, "+
				"for example `terraform import netgear_wax630e_ssid.main SSID1`.",
				key, strings.Join(keys, ", ")))
		return
	}
	var state wax630eSSIDModel
	state.fromWire(ctx, key, got, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key"), key)...)
}
