package fuzz

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/grpcweb"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
)

func FuzzGRPCWebFrame(f *testing.F) {
	f.Add(grpcweb.EncodeFrame(grpcweb.FlagData, []byte("abc")))
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Add([]byte{0x80, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		rd := bytes.NewReader(raw)
		for i := 0; i < 16; i++ {
			flag, payload, err := grpcweb.ReadFrame(rd, 1<<16)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, grpcweb.ErrTruncated) && !errors.Is(err, grpcweb.ErrFrameTooLarge) {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if len(payload) > 1<<16 {
				t.Fatal("frame over limit accepted")
			}
			again := grpcweb.EncodeFrame(flag, payload)
			if _, p2, err := grpcweb.ReadFrame(bytes.NewReader(again), 0); err != nil || !bytes.Equal(p2, payload) {
				t.Fatalf("round trip: %v", err)
			}
		}
		_, _, _ = grpcweb.DecodeResponse(raw, false)
		_, _, _ = grpcweb.DecodeResponse(raw, true)
	})
}

type fakeExchange struct{}

func (fakeExchange) Exchange(context.Context, *authv1.ExchangeRequest, ...grpc.CallOption) (*authv1.ExchangeResponse, error) {
	return nil, status.Error(codes.Unauthenticated, "no_session")
}

func FuzzBearerToken(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := authclient.New(authclient.Config{Issuer: "https://platform.example.org"}, authclient.StaticKeys{"k1": pub}, nil)
	_ = v.Start(context.Background(), nil)
	f.Add("Bearer eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.e30.AA")
	f.Add("Bearer ")
	f.Add("Basic dXNlcjpwYXNz")
	f.Add("")
	f.Fuzz(func(t *testing.T, header string) {
		tok := authclient.BearerToken(header)
		if tok == "" {
			return
		}
		r, err := identity.New(identity.Options{Sessions: fakeExchange{}, Verifier: v, KV: registry.NewMemory()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ResolveToken(context.Background(), tok); err == nil {
			t.Fatalf("token accepted without a valid signature: %q", tok)
		}
	})
}

func FuzzPathNormalize(f *testing.F) {
	for _, s := range []string{"/", "/a/b/", "/a/%2e%2e/b", "/a//b", "//", "/%2F"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := route.Normalize(s)
		if !ok {
			return
		}
		again, ok2 := route.Normalize(n)
		if !ok2 || again != n {
			t.Fatalf("normalisation is not idempotent: %q → %q → %q (%v)", s, n, again, ok2)
		}
	})
}
