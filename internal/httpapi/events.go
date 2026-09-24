package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// EventsHeartbeat is the SSE comment interval; EventsMaxAge ends a stream so
// clients reconnect (and re-authenticate) regularly.
const (
	EventsHeartbeat = 15 * time.Second
	EventsMaxAge    = 10 * time.Minute
	eventsPoll      = 2 * time.Second
)

// events streams registry changes and ability-version changes as
// server-sent events: `event: registry` (kind, module, version) and
// `event: abilities` (version). The shell refetches on either.
func (s *Server) events(d ShellDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequireIdentity(w, r, d.Identity)
		if !ok {
			return
		}
		flusher, canFlush := w.(http.Flusher)
		if !canFlush {
			Fail(w, r, nil, ErrUnavailable)
			return
		}
		var cursor uint64
		if c := r.Header.Get("Last-Event-ID"); c != "" {
			cursor, _ = strconv.ParseUint(c, 10, 64)
		}
		events, stop := d.Reg.Watch(cursor)
		defer stop()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "retry: 3000\n: connected %d\n\n", d.Reg.Version())
		flusher.Flush()
		lastVersion := d.Decide.TenantVersion(id.TenantID)
		heartbeat := time.NewTicker(EventsHeartbeat)
		defer heartbeat.Stop()
		poll := time.NewTicker(eventsPoll)
		defer poll.Stop()
		deadline := time.NewTimer(EventsMaxAge)
		defer deadline.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				return
			case <-heartbeat.C:
				_, _ = fmt.Fprint(w, ": ping\n\n")
				flusher.Flush()
			case <-poll.C:
				if v := d.Decide.TenantVersion(id.TenantID); v != lastVersion {
					lastVersion = v
					_, _ = fmt.Fprintf(w, "event: abilities\ndata: {\"version\":%q}\n\n", v)
					flusher.Flush()
				}
			case ev, open := <-events:
				if !open {
					return // overflow: the client reconnects from Last-Event-ID
				}
				_, _ = fmt.Fprintf(w, "id: %d\nevent: registry\ndata: {\"kind\":%q,\"module\":%q,\"version\":%d}\n\n", ev.Version, ev.Kind, ev.Module, ev.Version)
				flusher.Flush()
			}
		}
	}
}
