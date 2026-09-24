package identity

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
)

// RevocationFeed is auth.v1.Sessions/RevokedSince.
type RevocationFeed interface {
	RevokedSince(ctx context.Context, in *authv1.RevokedSinceRequest, opts ...grpc.CallOption) (*authv1.RevokedSinceResponse, error)
}

// RevocationWatcher polls the auth revocation feed and reports each mark as
// a subject key ("session:<id>", "user:<id>", "tenant:<id>") so long-lived
// streams of revoked principals can be terminated (FR-025).
type RevocationWatcher struct {
	Feed     RevocationFeed
	OnRevoke func(subject, reason string)
	Poll     time.Duration // default 5s
	Logger   *slog.Logger
	cursor   string
}

// Tick fetches new revocations once.
func (w *RevocationWatcher) Tick(ctx context.Context) error {
	resp, err := w.Feed.RevokedSince(ctx, &authv1.RevokedSinceRequest{Cursor: w.cursor, Limit: 1000})
	if err != nil {
		return err
	}
	for _, r := range resp.GetRevocations() {
		if w.OnRevoke != nil {
			w.OnRevoke(r.GetKind()+":"+r.GetSubjectId(), r.GetReason())
		}
	}
	if resp.GetNextCursor() != "" {
		w.cursor = resp.GetNextCursor()
	}
	return nil
}

// Run polls until ctx ends.
func (w *RevocationWatcher) Run(ctx context.Context) {
	poll := w.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.Tick(ctx); err != nil && w.Logger != nil {
				w.Logger.Warn("revocation feed", "err", err)
			}
		}
	}
}
