package known

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

const idSMS = "spiffe://example.org/svc/sms-gw"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// recording is a known store that keeps every write; fail makes writes fail.
type recording struct {
	mu     sync.Mutex
	writes []store.KnownModule
	fail   error
	block  chan struct{} // non-nil: writes wait until closed
}

func (s *recording) SeeKnown(ctx context.Context, m store.KnownModule) error {
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.writes = append(s.writes, m)
	return nil
}

func (s *recording) count(module string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, w := range s.writes {
		if w.Module == module {
			n++
		}
	}
	return n
}

func (s *recording) last(module string) (store.KnownModule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.writes) - 1; i >= 0; i-- {
		if s.writes[i].Module == module {
			return s.writes[i], true
		}
	}
	return store.KnownModule{}, false
}

type harness struct {
	ctx context.Context
	clk *clock
	reg *registry.Registry
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)}
	kv := registry.NewMemory()
	kv.Now = clk.now
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a1", SpiffeID: idSMS, Prefixes: []string{"/api/sms-gw"}, Names: []string{"sms-gw"}})
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg, err := registry.New(registry.Options{KV: kv, Allow: ms, Marks: ms, Audit: aw, TTL: 30 * time.Second, Renew: 10 * time.Second, Now: clk.now, Origin: "gw-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Load(ctx); err != nil {
		t.Fatal(err)
	}
	return &harness{ctx: ctx, clk: clk, reg: reg}
}

func register(t *testing.T, h *harness, instance, build string) registry.Lease {
	t.Helper()
	l, err := h.reg.Register(h.ctx, idSMS, &gatewayv1.RegisterRequest{InstanceId: instance, BuildVersion: build,
		Backend: &gatewayv1.Backend{HttpUrl: "https://127.0.0.1:1", GrpcTarget: "127.0.0.1:2"},
		Manifest: &gatewayv1.Manifest{Module: "sms-gw", DisplayName: "SMS Gateway", Version: "1.0.0", Prefixes: []string{"/api/sms-gw"},
			Routes:      []*gatewayv1.Route{{Method: "GET", Path: "/api/sms-gw/ping", Public: true}},
			Methods:     []*gatewayv1.Method{{FullMethod: "/smsgw.v1.Svc/Get", Permission: "sms-gw:read"}},
			Permissions: []*gatewayv1.Permission{{Resource: "sms-gw", Action: "read"}},
			Remote:      &gatewayv1.Remote{Entry: "/m/sms-gw/mf-manifest.json", Exposes: []string{"./routes"}},
			Nav:         []*gatewayv1.NavEntry{{Title: "SMS", Path: "/sms-gw", Order: 1, Requires: "sms-gw:read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func start(t *testing.T, h *harness, st Store, interval time.Duration) (*Recorder, *strings.Builder) {
	t.Helper()
	var logs strings.Builder
	var mu sync.Mutex
	r := &Recorder{Reg: h.reg, Store: st, Interval: interval, Now: h.clk.now,
		Logger: slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }), nil))}
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return r, &logs
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A module already registered when the recorder starts is recorded; later
// registrations and withdrawals are recorded from the event stream, the
// withdrawal with its own time as last seen.
func TestRecordsRegistrationsAndWithdrawals(t *testing.T) {
	h := newHarness(t)
	l := register(t, h, "i1", "4.1.1")
	st := &recording{}
	start(t, h, st, time.Hour)
	eventually(t, "startup record", func() bool { return st.count("sms-gw") == 1 })
	m, _ := st.last("sms-gw")
	if m.Identity != idSMS || m.DisplayName != "SMS Gateway" || m.LastVersion != "4.1.1" || m.ManifestHash == "" || !m.LastSeenAt.Equal(h.clk.now()) {
		t.Fatalf("%+v", m)
	}

	// A second instance on a newer build: the newest version is recorded.
	h.clk.add(time.Minute)
	l2 := register(t, h, "i2", "4.2.0")
	eventually(t, "update record", func() bool { m, _ := st.last("sms-gw"); return m.LastVersion == "4.2.0" })

	// Both instances leave: the withdrawal is recorded at its own time.
	h.clk.add(time.Minute)
	gone := h.clk.now()
	if err := h.reg.Deregister(h.ctx, idSMS, l.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.reg.Deregister(h.ctx, idSMS, l2.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "withdrawal record", func() bool { m, _ := st.last("sms-gw"); return m.LastSeenAt.Equal(gone) && m.LastVersion == "4.2.0" })
}

// Renewals every 10 s never write (SR-006); the periodic refresh writes each
// registered module once per interval.
func TestRenewalsDoNotWriteRefreshDoes(t *testing.T) {
	h := newHarness(t)
	st := &recording{}
	r, _ := start(t, h, st, time.Hour)
	l := register(t, h, "i1", "4.2.0")
	eventually(t, "registration record", func() bool { return st.count("sms-gw") == 1 })
	for i := 0; i < 30; i++ {
		h.clk.add(10 * time.Second)
		if _, err := h.reg.Renew(h.ctx, idSMS, l.ID); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := st.count("sms-gw"); n != 1 {
		t.Fatalf("renewals wrote: %d writes", n)
	}
	r.Refresh(h.ctx)
	if n := st.count("sms-gw"); n != 2 {
		t.Fatalf("refresh writes %d", n)
	}
	if m, _ := st.last("sms-gw"); !m.LastSeenAt.Equal(h.clk.now()) {
		t.Fatalf("refresh last seen %v", m.LastSeenAt)
	}
}

// A failing store neither stops the recorder nor floods the log: the next
// refresh writes again, and the failure is logged once until it recovers.
func TestStoreFailuresAreRetried(t *testing.T) {
	h := newHarness(t)
	register(t, h, "i1", "4.2.0")
	st := &recording{fail: errors.New("db down")}
	r, logs := start(t, h, st, time.Hour)
	time.Sleep(20 * time.Millisecond)
	r.Refresh(h.ctx)
	r.Refresh(h.ctx)
	if st.count("sms-gw") != 0 {
		t.Fatal("failed writes recorded")
	}
	if n := strings.Count(logs.String(), "known modules: store unavailable"); n != 1 {
		t.Fatalf("failure logged %d times:\n%s", n, logs.String())
	}
	st.mu.Lock()
	st.fail = nil
	st.mu.Unlock()
	r.Refresh(h.ctx)
	if st.count("sms-gw") != 1 {
		t.Fatal("not retried after recovery")
	}
	if strings.Contains(logs.String(), "db down") {
		t.Fatal("store error detail logged") // the detail may carry DSN fragments
	}
}

// When the registry closes the event stream on overflow, the recorder
// subscribes again and refreshes, so no registration is missed.
func TestResyncAfterWatchOverflow(t *testing.T) {
	h := newHarness(t)
	st := &recording{block: make(chan struct{})}
	start(t, h, st, time.Hour)
	// The recorder is stuck in a write; more than 64 events overflow its stream.
	l := register(t, h, "i1", "4.2.0")
	for i := 0; i < 80; i++ {
		if err := h.reg.Deregister(h.ctx, idSMS, l.ID); err != nil {
			t.Fatal(err)
		}
		l = register(t, h, "i1", "4.2.0")
	}
	close(st.block)
	eventually(t, "resync record", func() bool { return st.count("sms-gw") >= 1 })
}

// Registration and renewal never wait for the store (FR-004, SC-002).
func TestRegistrationDoesNotWaitForTheStore(t *testing.T) {
	h := newHarness(t)
	st := &recording{block: make(chan struct{})} // never released
	start(t, h, st, time.Hour)
	begin := time.Now()
	l := register(t, h, "i1", "4.2.0")
	for i := 0; i < 5; i++ {
		if _, err := h.reg.Renew(h.ctx, idSMS, l.ID); err != nil {
			t.Fatal(err)
		}
	}
	register(t, h, "i2", "4.2.0")
	if d := time.Since(begin); d > 100*time.Millisecond {
		t.Fatalf("registration waited for the store: %v", d)
	}
}
