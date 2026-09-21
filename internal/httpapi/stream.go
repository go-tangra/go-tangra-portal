package httpapi

import (
	"context"
	"net/http"

	"github.com/go-freya/freya/services/gateway/internal/stream"
)

// EventHub is the platform realtime bus the gateway fans out to browsers.
// *stream.Hub satisfies it.
type EventHub interface {
	Subscribe(ctx context.Context, tenantID, userID, lastID string) (*stream.Subscription, error)
}

// userStream is the single per-signed-in-user SSE endpoint any module publishes
// to (via the shared platform:events:<tenant> Valkey stream). It authenticates
// with the session cookie / platform token like every other shell route, scopes
// events to the caller's tenant + user, and replays from Last-Event-ID.
func (s *Server) userStream(d ShellDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequireIdentity(w, r, d.Identity)
		if !ok {
			return
		}
		if d.Hub == nil {
			Fail(w, r, nil, ErrUnavailable)
			return
		}
		sub, err := d.Hub.Subscribe(r.Context(), id.TenantID, id.UserID, r.Header.Get("Last-Event-ID"))
		if err != nil {
			Fail(w, r, nil, ErrUnavailable)
			return
		}
		stream.ServeSSE(w, r, sub, d.Instance, stream.Heartbeat, stream.MaxAge)
	}
}
