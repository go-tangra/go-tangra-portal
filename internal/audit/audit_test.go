package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type fakeIns struct {
	mu   sync.Mutex
	rows []store.AuditRow
	err  error
	n    int
}

func (f *fakeIns) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, rows...)
	return nil
}

func TestValidateAndRow(t *testing.T) {
	ok := Event{Type: RegistrationAccepted, Module: "orders", ActorKind: "service", ActorID: "spiffe://example.org/svc/orders", Outcome: "ok", TenantID: "t1",
		Details: map[string]any{"prefixes": []string{"/api/orders"}, "Authorization": "Bearer x", "session_cookie": "y", "access_token": "z", "api_key": "k"}}
	r, err := Row(ok, time.Unix(0, 0))
	if err != nil || r.EventType != "registration_accepted" || r.TenantID == nil || *r.TenantID != "t1" {
		t.Fatalf("%+v %v", r, err)
	}
	js := string(r.Details)
	if strings.Contains(js, "Bearer") || strings.Contains(js, "\"y\"") || strings.Contains(js, "\"z\"") || strings.Contains(js, "\"k\"") || !strings.Contains(js, "/api/orders") || strings.Count(js, "[REDACTED]") != 4 {
		t.Fatalf("redaction: %s", js)
	}
	for name, e := range map[string]Event{
		"unknown type": {Type: "made_up", ActorKind: "service", Outcome: "ok"},
		"bad outcome":  {Type: RegistrationRefused, ActorKind: "service", Outcome: "maybe"},
		"bad actor":    {Type: RegistrationRefused, ActorKind: "robot", Outcome: "ok"},
	} {
		if err := Validate(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Row(Event{Type: "x"}, time.Now()); err == nil {
		t.Fatal("row of invalid event")
	}
	if _, err := Row(Event{Type: LimitExceeded, ActorKind: "user", Outcome: "refused", Details: map[string]any{"bad": make(chan int)}}, time.Now()); err == nil {
		t.Fatal("unmarshalable detail")
	}
	if !Known("module_drained") || Known("x") {
		t.Fatal("Known")
	}
}

func TestWriterBatchesAndOverflow(t *testing.T) {
	ins := &fakeIns{}
	w := NewWriter(ins, nil)
	for i := 0; i < 450; i++ {
		if err := w.Emit(Event{Type: IdentityRefused, ActorKind: "user", Outcome: "refused"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Emit(Event{Type: "nope"}); err == nil {
		t.Fatal("invalid event queued")
	}
	w.Close()
	w.Close() // idempotent
	ins.mu.Lock()
	rows, calls := len(ins.rows), ins.n
	ins.mu.Unlock()
	if rows != 450 || calls < 3 {
		t.Fatalf("rows %d calls %d", rows, calls)
	}
	if err := w.Emit(Event{Type: IdentityRefused, ActorKind: "user", Outcome: "refused"}); err == nil || w.Lost() != 1 {
		t.Fatalf("emit after close: %v lost=%d", err, w.Lost())
	}
	// Queue overflow never blocks and reports via onError.
	var errs int
	var mu sync.Mutex
	w2 := newWriter(ins, func(error) { mu.Lock(); errs++; mu.Unlock() }, 1)
	_ = w2.Emit(Event{Type: IdentityRefused, ActorKind: "user", Outcome: "refused"})
	_ = w2.Emit(Event{Type: IdentityRefused, ActorKind: "user", Outcome: "refused"})
	mu.Lock()
	e := errs
	mu.Unlock()
	if e != 1 || w2.Lost() != 1 {
		t.Fatalf("overflow errs=%d lost=%d", e, w2.Lost())
	}
	// Store failures surface through onError and do not stop the writer.
	failing := &fakeIns{err: errors.New("db down")}
	var reported error
	w3 := NewWriter(failing, func(err error) { mu.Lock(); reported = err; mu.Unlock() })
	_ = w3.Emit(Event{Type: IdentityRefused, ActorKind: "user", Outcome: "refused"})
	w3.Close()
	mu.Lock()
	defer mu.Unlock()
	if reported == nil {
		t.Fatal("insert error not reported")
	}
}

func TestTickerFlush(t *testing.T) {
	ins := &fakeIns{}
	w := NewWriter(ins, nil)
	defer w.Close()
	_ = w.Emit(Event{Type: ModuleDrained, ActorKind: "operator", Outcome: "ok"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ins.mu.Lock()
		n := len(ins.rows)
		ins.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ticker did not flush")
}

func TestQuery(t *testing.T) {
	ctx := context.Background()
	m := memstore.New()
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	_ = m.InsertAuditRows(ctx, []store.AuditRow{{TS: now.Add(-time.Hour), EventType: "module_drained", Module: "a"}, {TS: now.Add(-48 * time.Hour), EventType: "module_drained", Module: "a"}})
	rows, err := Query(ctx, m, Filter{Module: "a"}, now)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v (default 24h window)", rows, err)
	}
	if rows, _ = Query(ctx, m, Filter{From: now.Add(-72 * time.Hour), Limit: 9999}, now); len(rows) != 2 {
		t.Fatal(rows)
	}
	if _, err := Query(ctx, m, Filter{EventType: "bogus"}, now); err == nil {
		t.Fatal("unknown type")
	}
	if _, err := Query(ctx, m, Filter{From: now.Add(time.Hour)}, now); err == nil {
		t.Fatal("from after to")
	}
}
