package stream

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testHub(t *testing.T) (*Hub, *Memory) {
	t.Helper()
	mem := NewMemory()
	h := NewHub(mem, Config{ReplayWindow: time.Hour, StreamsPerUser: 8, StreamsPerTenant: 64, MaxLen: 1000, ReadBlock: 50 * time.Millisecond}, slog.New(slog.DiscardHandler))
	t.Cleanup(h.Close)
	return h, mem
}

// A stream opened without Last-Event-ID starts at the tenant stream's tail and
// tells the browser so: its reconnect then replays what it missed even when
// no event reached it on the first connection.
func TestPositionLetsAReconnectReplay(t *testing.T) {
	h, _ := testHub(t)
	ctx := context.Background()
	old, err := h.PublishID(ctx, "t1", nil, true, "certificate.issued", map[string]any{"n": 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := h.Subscribe(ctx, "t1", "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Position() != old {
		t.Fatalf("position = %q, want the tail %q", sub.Position(), old)
	}
	sub.Close()

	// Published while the browser was reconnecting.
	missed, err := h.PublishID(ctx, "t1", nil, true, "certificate.failed", map[string]any{"n": 2}, false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := h.Subscribe(ctx, "t1", "u1", old)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	select {
	case ev := <-again.Events():
		if ev.ID != missed || ev.Type != "certificate.failed" {
			t.Fatalf("replayed %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missed event not replayed")
	}
}

func TestPositionEmptyStream(t *testing.T) {
	h, _ := testHub(t)
	sub, err := h.Subscribe(context.Background(), "t2", "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if sub.Position() != "" {
		t.Fatalf("position = %q", sub.Position())
	}
}

func TestServeSSESendsThePosition(t *testing.T) {
	h, _ := testHub(t)
	ctx := context.Background()
	tail, _ := h.PublishID(ctx, "t1", nil, true, "x.y", map[string]any{}, false)
	sub, err := h.Subscribe(ctx, "t1", "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "/gateway/v1/stream", nil).WithContext(rctx)
	w := httptest.NewRecorder()
	ServeSSE(w, r, sub, "gw-1", time.Hour, time.Hour)
	first, _, _ := strings.Cut(w.Body.String(), "\n\n")
	if !strings.Contains(first, "id: "+tail+"\n") || !strings.Contains(first, "retry: ") {
		t.Fatalf("first frame = %q", first)
	}
	if strings.Contains(first, "event:") || strings.Contains(first, "data:") {
		t.Fatalf("the position frame must not dispatch an event: %q", first)
	}
}
