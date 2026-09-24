// Package audit records gateway security events with a closed vocabulary and
// defensive redaction, batching writes to the store.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// EventType is the closed vocabulary of gateway audit events.
type EventType string

// Event types (data-model.md).
const (
	RegistrationAccepted  EventType = "registration_accepted"
	RegistrationRefused   EventType = "registration_refused"
	RegistrationUpdated   EventType = "registration_updated"
	RegistrationWithdrawn EventType = "registration_withdrawn"
	RenewalRefused        EventType = "renewal_refused"
	ModuleDrained         EventType = "module_drained"
	ModuleRevoked         EventType = "module_revoked"
	ModuleUnhealthy       EventType = "module_unhealthy"
	ModuleRecovered       EventType = "module_recovered"
	AllowlistChanged      EventType = "allowlist_changed"
	IdentityRefused       EventType = "identity_refused"
	PermissionRefused     EventType = "permission_refused"
	StreamTerminated      EventType = "stream_terminated"
	LimitExceeded         EventType = "limit_exceeded"
)

var known = map[EventType]struct{}{}

func init() {
	for _, t := range []EventType{RegistrationAccepted, RegistrationRefused, RegistrationUpdated, RegistrationWithdrawn, RenewalRefused,
		ModuleDrained, ModuleRevoked, ModuleUnhealthy, ModuleRecovered, AllowlistChanged, IdentityRefused, PermissionRefused, StreamTerminated, LimitExceeded} {
		known[t] = struct{}{}
	}
}

// Known reports whether t is in the vocabulary.
func Known(t string) bool { _, ok := known[EventType(t)]; return ok }

// Event is one audit record before persistence.
type Event struct {
	Type          EventType
	Module        string
	ActorKind     string // service | operator | user | system
	ActorID       string
	TenantID      string
	SubjectKind   string
	SubjectID     string
	Outcome       string // ok | refused | failed
	Reason        string
	CorrelationID string
	Details       map[string]any
}

// Inserter persists batches (implemented by the store; faked in tests).
type Inserter interface {
	InsertAuditRows(ctx context.Context, rows []store.AuditRow) error
}

// Writer buffers events and writes them in batches; Emit never blocks.
type Writer struct {
	ins     Inserter
	ch      chan store.AuditRow
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	lost    int64
	onError func(error)
	now     func() time.Time
}

// forbidden detail keys are redacted defensively even though callers never pass secrets.
var forbidden = []string{"password", "secret", "token", "key", "cookie", "authorization", "session"}

// NewWriter starts the batch writer (queue 10k, batch 200 or 500ms).
func NewWriter(ins Inserter, onError func(error)) *Writer {
	w := newWriter(ins, onError, 10000)
	w.wg.Add(1)
	go w.run()
	return w
}

func newWriter(ins Inserter, onError func(error), queue int) *Writer {
	w := &Writer{ins: ins, ch: make(chan store.AuditRow, queue), onError: onError, now: time.Now}
	if w.onError == nil {
		w.onError = func(error) {}
	}
	return w
}

// Validate checks the vocabulary and required fields.
func Validate(e Event) error {
	if _, ok := known[e.Type]; !ok {
		return fmt.Errorf("audit: unknown event type %q", e.Type)
	}
	switch e.Outcome {
	case "ok", "refused", "failed":
	default:
		return fmt.Errorf("audit: outcome %q", e.Outcome)
	}
	switch e.ActorKind {
	case "service", "operator", "user", "system":
	default:
		return fmt.Errorf("audit: actor_kind %q", e.ActorKind)
	}
	return nil
}

// Row converts an event to a store row, redacting forbidden detail keys.
func Row(e Event, now time.Time) (store.AuditRow, error) {
	if err := Validate(e); err != nil {
		return store.AuditRow{}, err
	}
	details := map[string]any{}
	for k, v := range e.Details {
		lk := strings.ToLower(k)
		redact := false
		for _, f := range forbidden {
			if strings.Contains(lk, f) {
				redact = true
			}
		}
		if redact {
			details[k] = "[REDACTED]"
		} else {
			details[k] = v
		}
	}
	js, err := json.Marshal(details)
	if err != nil {
		return store.AuditRow{}, err
	}
	r := store.AuditRow{TS: now, EventType: string(e.Type), Module: e.Module, ActorKind: e.ActorKind, ActorID: e.ActorID, SubjectKind: e.SubjectKind,
		SubjectID: e.SubjectID, Outcome: e.Outcome, Reason: e.Reason, CorrelationID: e.CorrelationID, Details: js}
	if e.TenantID != "" {
		v := e.TenantID
		r.TenantID = &v
	}
	return r, nil
}

// Emit validates and queues an event.
func (w *Writer) Emit(e Event) error {
	row, err := Row(e, w.now())
	if err != nil {
		return err
	}
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		w.mu.Lock()
		w.lost++
		w.mu.Unlock()
		return errors.New("audit: writer closed")
	}
	select {
	case w.ch <- row:
	default:
		w.mu.Lock()
		w.lost++
		w.mu.Unlock()
		w.onError(errors.New("audit: queue full, event lost"))
	}
	return nil
}

// Lost returns the number of events that could not be queued.
func (w *Writer) Lost() int64 { w.mu.Lock(); defer w.mu.Unlock(); return w.lost }

func (w *Writer) run() {
	defer w.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	buf := make([]store.AuditRow, 0, 200)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := w.ins.InsertAuditRows(ctx, buf); err != nil {
			w.onError(err)
		}
		cancel()
		buf = buf[:0]
	}
	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, r)
			if len(buf) >= 200 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Close drains and stops the writer.
func (w *Writer) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.ch)
	w.mu.Unlock()
	w.wg.Wait()
}
