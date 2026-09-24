package identity

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
)

type fakeFeed struct {
	calls   int
	cursors []string
	err     error
}

func (f *fakeFeed) RevokedSince(_ context.Context, in *authv1.RevokedSinceRequest, _ ...grpc.CallOption) (*authv1.RevokedSinceResponse, error) {
	f.calls++
	f.cursors = append(f.cursors, in.GetCursor())
	if f.err != nil {
		return nil, f.err
	}
	if f.calls == 1 {
		return &authv1.RevokedSinceResponse{NextCursor: "c1", Revocations: []*authv1.Revocation{{Kind: "session", SubjectId: "s1", Reason: "signout"}, {Kind: "user", SubjectId: "u1", Reason: "deactivated"}}}, nil
	}
	return &authv1.RevokedSinceResponse{NextCursor: ""}, nil
}

func TestRevocationWatcher(t *testing.T) {
	f := &fakeFeed{}
	var got []string
	w := &RevocationWatcher{Feed: f, OnRevoke: func(s, r string) { got = append(got, s+"="+r) }}
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "session:s1=signout" || f.cursors[1] != "c1" || w.cursor != "c1" {
		t.Fatalf("%v %v %q", got, f.cursors, w.cursor)
	}
	f.err = errors.New("down")
	if err := w.Tick(context.Background()); err == nil {
		t.Fatal("error swallowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	w.Poll = 5 * time.Millisecond
	w.Run(ctx)
	if f.calls < 4 {
		t.Fatalf("calls %d", f.calls)
	}
}

func TestRevocationWatcherLogsFailures(t *testing.T) {
	var buf strings.Builder
	f := &fakeFeed{err: errors.New("down")}
	w := &RevocationWatcher{Feed: f, Poll: 5 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	if !strings.Contains(buf.String(), "revocation feed") {
		t.Fatalf("failure not logged: %q", buf.String())
	}
}

func TestRevocationWatcherDefaultPoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &RevocationWatcher{Feed: &fakeFeed{}}
	w.Run(ctx) // default 5 s poll; returns at once on a cancelled context
}
