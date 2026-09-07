package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
	"netgear-tools/internal/xs508tm"
)

// Both switches expose the same idea - an HTTP listener and an HTTPS listener
// with session limits - through completely different APIs. The MS510TXUP
// splits them across access_http and access_https; the XS508TM keeps them in
// one http_config object. Two resources rather than one, because a shared
// schema would have to lie about which fields exist where.

// --- MS510TXUP --------------------------------------------------------------

var (
	_ resource.Resource                = &ms510WebAccessResource{}
	_ resource.ResourceWithImportState = &ms510WebAccessResource{}
)

type ms510WebAccessResource struct{ client *ms510txup.Client }

func NewMS510WebAccessResource() resource.Resource { return &ms510WebAccessResource{} }

type ms510WebAccessModel struct {
	HTTPEnabled        types.Bool  `tfsdk:"http_enabled"`
	HTTPSEnabled       types.Bool  `tfsdk:"https_enabled"`
	HTTPSPort          types.Int64 `tfsdk:"https_port"`
	SessionIdleMinutes types.Int64 `tfsdk:"session_idle_minutes"`
	SessionMaxHours    types.Int64 `tfsdk:"session_max_hours"`
	MaxSessions        types.Int64 `tfsdk:"max_sessions"`
	SSLv3Enabled       types.Bool  `tfsdk:"sslv3_enabled"`
	TLSv1Enabled       types.Bool  `tfsdk:"tlsv1_enabled"`
	CertificatePresent types.Bool  `tfsdk:"certificate_present"`
}

func (r *ms510WebAccessResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_web_access"
}

const webAccessCommon = "\n\n**Leaving HTTP enabled is deliberate.** The exporter for this switch " +
	"connects over plain HTTP, so turning it off means moving that endpoint in the same change " +
	"rather than afterwards. Until then HTTPS is additive: it removes the plaintext password for " +
	"anyone who uses it, without breaking what already works.\n\n" +
	"**`max_sessions` is capped at 4 by the firmware and is not really tunable.** It is modelled " +
	"because it explains a failure that looks like nothing else: once four sessions are held, " +
	"every login is refused. Slots are freed only after `session_idle_minutes`, so any tool that " +
	"exits without logging out burns one for that long."

func (r *ms510WebAccessResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "HTTP and HTTPS management listeners on the MS510TXUP." + webAccessCommon + "\n\n" +
			"**Certificate generation is not reachable from here.** `certificate_present` is " +
			"read-only, and `https_enabled = true` fails without a certificate. Generate one at " +
			"System > Protocols > HTTPS > Certificate > Generate Certificates - it is the single " +
			"step on this switch that genuinely needs a browser. Everything after that, including " +
			"enabling HTTPS, works over the API.\n\n" +
			"The generated certificate has `CN=Switch`, so it satisfies \"no plaintext password on " +
			"the wire\" and nothing more; it will never validate against a hostname. The same page " +
			"has a Certificate Upload section that takes a PEM file, which is the path for a real " +
			"one.",
		Attributes: map[string]schema.Attribute{
			"http_enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Plain-HTTP listener. True, because the exporter depends on it - see above.",
			},
			"https_enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Description: "HTTPS listener. Requires a certificate; the write is refused without one.",
			},
			"https_port": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "HTTPS port. 443 unless there is a reason.",
			},
			"session_idle_minutes": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "Idle minutes before a session is dropped, 5-60. Also the time a leaked " +
					"session slot stays leaked.",
			},
			"session_max_hours": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "Absolute session lifetime in hours, 1-168.",
			},
			"max_sessions": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "Concurrent session cap. The firmware maximum is 4.",
			},
			"sslv3_enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "SSLv3. Off, and there is no version of this network on which it should be on.",
			},
			"tlsv1_enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "TLS 1.0. Off. It exists for equipment that should not be on a network.",
			},
			"certificate_present": schema.BoolAttribute{
				Computed:    true,
				Description: "Read-only. Whether an HTTPS certificate is installed.",
			},
		},
	}
}

func (r *ms510WebAccessResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "web management access"); c != nil {
		r.client = c
	}
}

func (m *ms510WebAccessModel) fromWire(h, s ms510txup.WebAccess) {
	m.HTTPEnabled = types.BoolValue(h.Admin == 1)
	m.HTTPSEnabled = types.BoolValue(s.Admin == 1)
	m.HTTPSPort = types.Int64Value(int64(s.Port))
	m.SessionIdleMinutes = types.Int64Value(int64(s.SoftTimeout))
	m.SessionMaxHours = types.Int64Value(int64(s.HardTimeout))
	m.MaxSessions = types.Int64Value(int64(s.MaxSessions))
	m.SSLv3Enabled = types.BoolValue(s.SSLv3 == 1)
	m.TLSv1Enabled = types.BoolValue(s.TLSv1 == 1)
	m.CertificatePresent = types.BoolValue(s.Present == 1)
}

// apply writes HTTPS only. http_enabled is modelled so its state is visible in
// a plan, but is not written: the only value anyone would set is false, and
// that would cut the exporter's connection as a side effect of an apply.
func (r *ms510WebAccessResource) apply(plan *ms510WebAccessModel, diags diagSink) {
	cur, err := r.client.GetHTTPS()
	if err != nil {
		diags.AddError("Could not read the HTTPS settings", err.Error())
		return
	}
	want := cur
	want.Admin = boolToInt(plan.HTTPSEnabled.ValueBool())
	if v := plan.HTTPSPort; !v.IsNull() && !v.IsUnknown() {
		want.Port = int(v.ValueInt64())
	}
	if v := plan.SessionIdleMinutes; !v.IsNull() && !v.IsUnknown() {
		want.SoftTimeout = int(v.ValueInt64())
	}
	if v := plan.SessionMaxHours; !v.IsNull() && !v.IsUnknown() {
		want.HardTimeout = int(v.ValueInt64())
	}
	if v := plan.MaxSessions; !v.IsNull() && !v.IsUnknown() {
		want.MaxSessions = int(v.ValueInt64())
	}
	want.SSLv3 = boolToInt(plan.SSLv3Enabled.ValueBool())
	want.TLSv1 = boolToInt(plan.TLSv1Enabled.ValueBool())

	if err := r.client.SetHTTPS(want); err != nil {
		diags.AddError("Could not write the HTTPS settings", err.Error())
		return
	}
	gotS, err := r.client.GetHTTPS()
	if err != nil {
		diags.AddError("Could not read back the HTTPS settings", err.Error())
		return
	}
	gotH, err := r.client.GetHTTP()
	if err != nil {
		diags.AddError("Could not read the HTTP settings", err.Error())
		return
	}
	plan.fromWire(gotH, gotS)
}

func (r *ms510WebAccessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510WebAccessModel
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

func (r *ms510WebAccessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510WebAccessModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := r.client.GetHTTP()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the HTTP settings", err.Error())
		return
	}
	s, err := r.client.GetHTTPS()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the HTTPS settings", err.Error())
		return
	}
	state.fromWire(h, s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510WebAccessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510WebAccessModel
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

// Delete DOES NOTHING. Disabling HTTPS on destroy would push management back
// to plaintext-only as a side effect of removing a resource from a config
// file, which is the wrong direction for a security control.
func (r *ms510WebAccessResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *ms510WebAccessResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	h, err := r.client.GetHTTP()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the HTTP settings", err.Error())
		return
	}
	s, err := r.client.GetHTTPS()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the HTTPS settings", err.Error())
		return
	}
	var state ms510WebAccessModel
	state.fromWire(h, s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// --- XS508TM ----------------------------------------------------------------

var (
	_ resource.Resource                = &xs508WebAccessResource{}
	_ resource.ResourceWithImportState = &xs508WebAccessResource{}
)

type xs508WebAccessResource struct{ client *xs508tm.Client }

func NewXS508WebAccessResource() resource.Resource { return &xs508WebAccessResource{} }

type xs508WebAccessModel struct {
	HTTPEnabled        types.Bool  `tfsdk:"http_enabled"`
	HTTPSEnabled       types.Bool  `tfsdk:"https_enabled"`
	HTTPPort           types.Int64 `tfsdk:"http_port"`
	HTTPSPort          types.Int64 `tfsdk:"https_port"`
	SessionIdleMinutes types.Int64 `tfsdk:"session_idle_minutes"`
	SessionMaxHours    types.Int64 `tfsdk:"session_max_hours"`
	MaxSessions        types.Int64 `tfsdk:"max_sessions"`
	CertificatePresent types.Bool  `tfsdk:"certificate_present"`
}

func (r *xs508WebAccessResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_web_access"
}

func (r *xs508WebAccessResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "HTTP and HTTPS management listeners on the XS508TM." + webAccessCommon + "\n\n" +
			"**This switch shipped with a certificate already generated** - dated at manufacture, " +
			"`CN=Switch` - so unlike the MS510TXUP, enabling HTTPS here needs no browser step. It " +
			"is still self-signed and will never validate against a hostname; `https_cert_upld` is " +
			"the route for a real one.",
		Attributes: map[string]schema.Attribute{
			"http_enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Plain-HTTP listener. True, because the exporter depends on it.",
			},
			"https_enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Description: "HTTPS listener. Refused when no certificate is installed.",
			},
			"http_port":  schema.Int64Attribute{Optional: true, Computed: true, Description: "HTTP port, normally 80."},
			"https_port": schema.Int64Attribute{Optional: true, Computed: true, Description: "HTTPS port, normally 443."},
			"session_idle_minutes": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "Idle minutes before a session is dropped, and the time a leaked slot stays leaked.",
			},
			"session_max_hours": schema.Int64Attribute{Optional: true, Computed: true, Description: "Absolute session lifetime, hours."},
			"max_sessions":      schema.Int64Attribute{Optional: true, Computed: true, Description: "Concurrent session cap; firmware maximum 4."},
			"certificate_present": schema.BoolAttribute{
				Computed:    true,
				Description: "Read-only. Whether an HTTPS certificate is installed.",
			},
		},
	}
}

func (r *xs508WebAccessResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.XS508TM == nil {
		resp.Diagnostics.AddError("XS508TM not configured",
			"This resource manages the XS508TM. Add an `xs508tm` block to the provider, or set XS508TM_PASSWORD.")
		return
	}
	r.client = c.XS508TM
}

func (m *xs508WebAccessModel) fromWire(h xs508tm.HTTPConfig, cert xs508tm.CertStatus) {
	m.HTTPEnabled = types.BoolValue(h.HTTPEnable == 1)
	m.HTTPSEnabled = types.BoolValue(h.HTTPSEnable == 1)
	m.HTTPPort = types.Int64Value(int64(h.HTTPPort))
	m.HTTPSPort = types.Int64Value(int64(h.HTTPSPort))
	m.SessionIdleMinutes = types.Int64Value(int64(h.SoftTimeout))
	m.SessionMaxHours = types.Int64Value(int64(h.HardTimeout))
	m.MaxSessions = types.Int64Value(int64(h.MaxSessions))
	m.CertificatePresent = types.BoolValue(cert.CertStatus == 1)
}

func (r *xs508WebAccessResource) read() (xs508tm.HTTPConfig, xs508tm.CertStatus, error) {
	h, err := r.client.GetHTTPConfig()
	if err != nil {
		return h, xs508tm.CertStatus{}, err
	}
	c, err := r.client.GetCertStatus()
	return h, c, err
}

// apply writes the whole http_config row, as this firmware expects, but never
// turns HTTP off - see the note on the MS510TXUP resource's apply.
func (r *xs508WebAccessResource) apply(plan *xs508WebAccessModel, diags diagSink) {
	cur, cert, err := r.read()
	if err != nil {
		diags.AddError("Could not read the web access settings", err.Error())
		return
	}
	if plan.HTTPSEnabled.ValueBool() && cert.CertStatus == 0 {
		diags.AddError("No certificate installed",
			"HTTPS cannot be enabled without a certificate. Upload one with https_cert_upld.")
		return
	}
	want := cur
	want.HTTPSEnable = boolToInt(plan.HTTPSEnabled.ValueBool())
	if v := plan.HTTPSPort; !v.IsNull() && !v.IsUnknown() {
		want.HTTPSPort = int(v.ValueInt64())
	}
	if v := plan.SessionIdleMinutes; !v.IsNull() && !v.IsUnknown() {
		want.SoftTimeout = int(v.ValueInt64())
	}
	if v := plan.SessionMaxHours; !v.IsNull() && !v.IsUnknown() {
		want.HardTimeout = int(v.ValueInt64())
	}
	if v := plan.MaxSessions; !v.IsNull() && !v.IsUnknown() {
		want.MaxSessions = int(v.ValueInt64())
	}
	if err := r.client.SetHTTPConfig(want); err != nil {
		diags.AddError("Could not write the web access settings", err.Error())
		return
	}
	gotH, gotC, err := r.read()
	if err != nil {
		diags.AddError("Could not read back the web access settings", err.Error())
		return
	}
	plan.fromWire(gotH, gotC)
}

func (r *xs508WebAccessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan xs508WebAccessModel
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

func (r *xs508WebAccessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state xs508WebAccessModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, c, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the web access settings", err.Error())
		return
	}
	state.fromWire(h, c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *xs508WebAccessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan xs508WebAccessModel
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

// Delete DOES NOTHING, for the same reason as the MS510TXUP resource.
func (r *xs508WebAccessResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *xs508WebAccessResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	h, c, err := r.read()
	if err != nil {
		resp.Diagnostics.AddError("Could not read the web access settings", err.Error())
		return
	}
	var state xs508WebAccessModel
	state.fromWire(h, c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
