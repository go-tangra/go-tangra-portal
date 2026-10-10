package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

const deliverHost = "0190f7c2-6a3e-7c1a-9b2e-000000000001"

// fakeInventory is the inventory's ModuleDeliveryService.
type fakeInventory struct {
	created []*inventoryv1.CreateModuleDeliveryRequest
	err     error
	state   inventoryv1.ModuleDeliveryState
	tenants []string
}

func (f *fakeInventory) CreateModuleDelivery(_ context.Context, in *inventoryv1.CreateModuleDeliveryRequest, _ ...grpc.CallOption) (*inventoryv1.ModuleDelivery, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.created = append(f.created, in)
	return &inventoryv1.ModuleDelivery{ItemId: "item-1", DeliveryId: in.GetDeliveryId(), HostId: in.GetHostId(), Hostname: "pbx1", Module: in.GetModule(),
		State: inventoryv1.ModuleDeliveryState_MODULE_DELIVERY_STATE_PENDING, HookExitCode: -1, AgentOnline: true, Created: true}, nil
}

func (f *fakeInventory) GetModuleDelivery(_ context.Context, in *inventoryv1.GetModuleDeliveryRequest, _ ...grpc.CallOption) (*inventoryv1.ModuleDelivery, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.tenants = append(f.tenants, in.GetTenantId())
	return &inventoryv1.ModuleDelivery{DeliveryId: in.GetDeliveryId(), HostId: deliverHost, Hostname: "pbx1", State: f.state, Reason: "", HookExitCode: 0, AgentOnline: true}, nil
}

func (f *fakeInventory) ListModuleTargets(_ context.Context, in *inventoryv1.ListModuleTargetsRequest, _ ...grpc.CallOption) (*inventoryv1.ListModuleTargetsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.tenants = append(f.tenants, in.GetTenantId())
	return &inventoryv1.ListModuleTargetsResponse{Hosts: []*inventoryv1.ModuleTarget{
		{HostId: deliverHost, Hostname: "pbx1", OsName: "Ubuntu", AgentOnline: true, Capability: "enabled", IpAddresses: []string{"10.0.0.5"}},
		{HostId: "0190f7c2-6a3e-7c1a-9b2e-000000000002", Hostname: "win1", OsName: "Windows", Capability: "not_supported_platform"},
	}}, nil
}

const deliverBody = `{"host_id":"` + deliverHost + `","inputs":{"MODULE_ADVERTISE_HOST":"pbx1.example.org"},"ttl_hours":6}`

// US1: an administrator delivers a module to an enrolled host; nothing is
// minted or rendered until the agent fetches.
func TestDeliverModule(t *testing.T) {
	inv := &fakeInventory{}
	e := newJoinEnvWith(t, true, inv)
	w := do(e.s, "POST", "/gateway/v1/ops/catalogue/sms-gw/deliver", deliverBody, adminHdr("operator"))
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out struct {
		JoinID   string       `json:"join_id"`
		Delivery DeliveryView `json:"delivery"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.JoinID == "" || out.Delivery.State != "pending" || out.Delivery.HookExitCode != nil {
		t.Fatalf("%s", w.Body)
	}
	if len(e.auth.got) != 0 {
		t.Fatal("token minted before the agent fetched")
	}
	j := e.ms.Joins[out.JoinID]
	if j.Channel != store.JoinAgent || j.HostID != deliverHost || j.TenantID != "platform" || j.Inputs["MODULE_ADVERTISE_HOST"] != "pbx1.example.org" || j.JTI != "" ||
		j.ExpiresAt.Sub(j.CreatedAt) != 6*time.Hour {
		t.Fatalf("%+v", j)
	}
	c := inv.created[0]
	if c.GetDeliveryId() != out.JoinID || c.GetTenantId() != "platform" || c.GetHostId() != deliverHost || c.GetModule() != "sms-gw" || c.GetVersion() != "4.3.0" ||
		c.GetExpiresAt() != j.ExpiresAt.Unix() {
		t.Fatalf("%+v", c)
	}
	if allow, _ := e.ms.ListAllow(context.Background()); len(allow) != 1 {
		t.Fatalf("allow-list: %d", len(allow))
	}
	// Progress shows the delivery, and the token once rendered.
	inv.state = inventoryv1.ModuleDeliveryState_MODULE_DELIVERY_STATE_INSTALLED
	w = do(e.s, "GET", "/gateway/v1/ops/catalogue/sms-gw/join/"+out.JoinID, "", adminHdr("operator"))
	var p JoinProgress
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	if w.Code != 200 || p.Channel != "agent" || p.Delivery == nil || p.Delivery.State != "installed" || p.Delivery.HookExitCode == nil || p.TokenUsed || p.Partial {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	e.aw.Close()
	var audited bool
	for _, r := range e.ms.Audit() {
		if r.EventType == "module_join_bundle" && strings.Contains(string(r.Details), `"channel":"agent"`) && strings.Contains(string(r.Details), deliverHost) {
			audited = true
		}
	}
	if !audited {
		t.Fatal("delivery not audited")
	}
}

func TestDeliverRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		who, body string
		invErr    error
		noInv     bool
		want      int
		reason    string
	}{
		"not admin":        {"operator-only", deliverBody, nil, false, 403, ""},
		"bad host id":      {"operator", `{"host_id":"x","inputs":{"MODULE_ADVERTISE_HOST":"a.b"}}`, nil, false, 400, ""},
		"bad input":        {"operator", `{"host_id":"` + deliverHost + `","inputs":{"MODULE_ADVERTISE_HOST":"A B"}}`, nil, false, 400, ""},
		"ttl":              {"operator", `{"host_id":"` + deliverHost + `","inputs":{"MODULE_ADVERTISE_HOST":"a.b"},"ttl_hours":48}`, nil, false, 400, ""},
		"not configured":   {"operator", deliverBody, nil, true, 503, ""},
		"unknown host":     {"operator", deliverBody, status.Error(codes.NotFound, "host"), false, 404, ""},
		"no agent":         {"operator", deliverBody, status.Error(codes.FailedPrecondition, "no_agent"), false, 409, "no_agent"},
		"disabled":         {"operator", deliverBody, status.Error(codes.FailedPrecondition, "disabled_on_server"), false, 409, "disabled_on_server"},
		"odd precondition": {"operator", deliverBody, status.Error(codes.FailedPrecondition, "<script>"), false, 409, "not_eligible"},
		"inventory down":   {"operator", deliverBody, status.Error(codes.Unavailable, "down"), false, 503, ""},
	} {
		t.Run(name, func(t *testing.T) {
			inv := &fakeInventory{err: tc.invErr}
			var client inventoryv1.ModuleDeliveryServiceClient = inv
			if tc.noInv {
				client = nil
			}
			e := newJoinEnvWith(t, true, client)
			w := do(e.s, "POST", "/gateway/v1/ops/catalogue/sms-gw/deliver", tc.body, adminHdr(tc.who))
			if w.Code != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if tc.reason != "" && !strings.Contains(w.Body.String(), `"reason":"`+tc.reason+`"`) {
				t.Fatalf("%s", w.Body)
			}
			if len(e.auth.got) != 0 {
				t.Fatal("a delivery minted a token")
			}
		})
	}
}

func TestDeliverTargets(t *testing.T) {
	inv := &fakeInventory{}
	e := newJoinEnvWith(t, true, inv)
	w := do(e.s, "GET", "/gateway/v1/ops/catalogue/sms-gw/targets?q=pbx", "", adminHdr("operator"))
	var out struct {
		Hosts []TargetView `json:"hosts"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || len(out.Hosts) != 2 || out.Hosts[0].Capability != "enabled" || out.Hosts[0].IPAddresses[0] != "10.0.0.5" || out.Hosts[1].IPAddresses == nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if v, _ := catalogue(t, e.s, "operator"); !v.CanDeliver {
		t.Fatal("can_deliver false with agent delivery configured")
	}
	if v, _ := catalogue(t, newJoinEnv(t, true).s, "operator"); v.CanDeliver {
		t.Fatal("can_deliver true without inventory")
	}
	if inv.tenants[0] != "platform" {
		t.Fatalf("tenant %v", inv.tenants)
	}
	for name, tc := range map[string]struct {
		path, who string
		want      int
	}{
		"not admin":  {"/gateway/v1/ops/catalogue/sms-gw/targets", "operator-only", 403},
		"no entry":   {"/gateway/v1/ops/catalogue/billing/targets", "operator", 404},
		"long query": {"/gateway/v1/ops/catalogue/sms-gw/targets?q=" + strings.Repeat("a", 65), "operator", 400},
	} {
		if w := do(e.s, "GET", tc.path, "", adminHdr(tc.who)); w.Code != tc.want {
			t.Errorf("%s → %d %s", name, w.Code, w.Body)
		}
	}
	if w := do(newJoinEnv(t, true).s, "GET", "/gateway/v1/ops/catalogue/sms-gw/targets", "", adminHdr("operator")); w.Code != 503 {
		t.Fatalf("not configured → %d", w.Code)
	}
}
