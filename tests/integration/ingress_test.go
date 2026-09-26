//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/grpcproxy/echov1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/grpcweb"
)

func decodeJSON(resp *http.Response, v any) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// grpcClient dials the public edge as an external gRPC client.
func (p *Platform) grpcClient() echov1.EchoClient {
	p.T.Helper()
	conn, err := grpc.NewClient(strings.TrimPrefix(p.Base, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}))) //nolint:gosec // dev cert
	if err != nil {
		p.T.Fatal(err)
	}
	p.T.Cleanup(func() { _ = conn.Close() })
	return echov1.NewEchoClient(conn)
}

func bearer(ctx context.Context, tok string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
}

func TestSigninThroughGateway(t *testing.T) {
	e := Start(t)
	// Anonymous: the gateway API refuses; the auth module is reachable through the gateway.
	if code, body := e.JSON(http.MethodGet, "/gateway/v1/me", nil); code != 401 || body["reason"] != "unauthenticated" {
		t.Fatalf("me → %d %v", code, body)
	}
	if code, _ := e.JSON(http.MethodGet, "/api/v1/session", nil); code != 401 {
		t.Fatalf("auth session via gateway → %d", code)
	}
	_, accept := e.Bootstrap("ops@example.org")
	if code, body := e.JSON(http.MethodGet, "/api/v1/tenants/resolve?slug=platform", nil); code != 200 {
		t.Fatalf("auth routes not forwarded: %d %v", code, body)
	}
	e.AcceptOperator(accept, "correct horse battery staple 42")
	if code, body := e.SignInAt("platform", "ops@example.org", "correct horse battery staple 42"); code != 200 {
		t.Fatalf("sign-in → %d %v", code, body)
	}
	// The session cookie lives on the gateway origin and identifies the caller everywhere.
	if e.SessionCookie() == "" {
		t.Fatal("session cookie not set on the gateway origin")
	}
	code, me := e.JSON(http.MethodGet, "/gateway/v1/me", nil)
	if code != 200 || me["source"] != "session" || me["operator"] != true {
		t.Fatalf("me → %d %v", code, me)
	}
	if code, sess := e.JSON(http.MethodGet, "/api/v1/session", nil); code != 200 || sess["operator"] != true {
		t.Fatalf("auth session → %d %v", code, sess)
	}
	// Sign-out anywhere signs out everywhere.
	if code, _ := e.JSON(http.MethodPost, "/api/v1/signout", nil); code != 204 {
		t.Fatalf("signout → %d", code)
	}
	if code, _ := e.JSON(http.MethodGet, "/gateway/v1/me", nil); code != 401 {
		t.Fatalf("after signout → %d", code)
	}
	if n := e.auditCount("identity_refused", ""); n < 1 {
		t.Fatalf("identity_refused audits %d", n)
	}
}

func TestGRPCIngressAndBridge(t *testing.T) {
	p := StartPlatform(t)
	p.GrantSelf("alpha-reader", "alpha:alpha:read")
	tok := p.Token()
	c := p.grpcClient()
	ctx := context.Background()
	// Without a token: unauthenticated; unknown service: not found; public method works.
	if _, err := c.Unary(ctx, &echov1.Msg{Text: "x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous unary: %v", err)
	}
	cs, _ := c.ClientStream(ctx)
	_ = cs.Send(&echov1.Msg{Text: "a"})
	if m, err := cs.CloseAndRecv(); err != nil || m.Count != 1 {
		t.Fatalf("public client stream: %v %v", m, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var resp *echov1.Msg
	var err error
	for time.Now().Before(deadline) {
		resp, err = c.Unary(bearer(ctx, tok), &echov1.Msg{Text: "hi"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || !strings.Contains(resp.Text, "peer=gateway") || !strings.Contains(resp.Text, "authorization=Bearer ey") || !strings.Contains(resp.Text, "x-gateway-module=alpha") {
		t.Fatalf("unary: %v %v", resp, err)
	}
	ss, err := c.ServerStream(bearer(ctx, tok), &echov1.Msg{Text: "s", Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		if _, err := ss.Recv(); err != nil {
			break
		}
		n++
	}
	if n != 3 {
		t.Fatalf("server stream got %d", n)
	}
	// Audience confusion: a token issued for another audience is refused on the first call.
	if _, err := c.Unary(bearer(ctx, "eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJvdGhlciJ9.AA"), &echov1.Msg{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad token: %v", err)
	}
	// gRPC-web from the browser session (cookie + CSRF).
	raw, _ := proto.Marshal(&echov1.Msg{Text: "web", Count: 1})
	req, _ := http.NewRequest(http.MethodPost, p.Base+"/echo.v1.Echo/Unary", bytes.NewReader(grpcweb.EncodeFrame(grpcweb.FlagData, raw)))
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	req.Header.Set("X-CSRF-Token", p.CSRF(p.Base))
	req.Header.Set("Origin", p.Base)
	hr, err := p.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(hr.Body)
	hr.Body.Close()
	if hr.StatusCode != 200 || hr.Header.Get("Content-Type") != "application/grpc-web+proto" {
		t.Fatalf("grpc-web → %d %v %q", hr.StatusCode, hr.Header, body)
	}
	frames, trailers, err := grpcweb.DecodeResponse(body, false)
	if err != nil || len(frames) != 1 || trailers.Get("grpc-status")[0] != "0" {
		t.Fatalf("%v %v %v", frames, trailers, err)
	}
	var m echov1.Msg
	_ = proto.Unmarshal(frames[0], &m)
	if !strings.Contains(m.Text, "authorization=Bearer ey") || strings.Contains(m.Text, "cookie=") {
		t.Fatalf("%q", m.Text)
	}
	// Streams of a revoked session terminate within the propagation bound (FR-025).
	p.Echo.Delay.Store(int64(300 * time.Millisecond))
	long, err := c.ServerStream(bearer(ctx, tok), &echov1.Msg{Text: "s", Count: 200})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := long.Recv(); err != nil {
		t.Fatal(err)
	}
	if code, _ := p.JSON(http.MethodPost, "/api/v1/signout", nil); code != 204 {
		t.Fatalf("signout → %d", code)
	}
	start := time.Now()
	for err == nil {
		_, err = long.Recv()
	}
	if status.Code(err) != codes.PermissionDenied || time.Since(start) > 15*time.Second {
		t.Fatalf("revoked stream ended with %v after %s", err, time.Since(start))
	}
	if n := p.auditCount("stream_terminated", ""); n < 0 {
		t.Fatal("unreachable")
	}
}

func TestDecisionOutageFailsClosed(t *testing.T) {
	p := StartPlatform(t)
	p.GrantSelf("alpha-reader", "alpha:alpha:read")
	p.waitStatus("/api/alpha/secret", 200, 10*time.Second)
	// Kill the auth module: public routes keep working, protected ones fail closed.
	_ = p.Auth.Process.Kill()
	time.Sleep(3 * time.Second)
	if code, body := p.JSON(http.MethodGet, "/api/alpha/ping", nil); code != 200 {
		t.Fatalf("public during outage → %d %v", code, body)
	}
	deadline := time.Now().Add(15 * time.Second)
	var code int
	var body map[string]any
	for time.Now().Before(deadline) {
		code, body = p.JSON(http.MethodGet, "/api/alpha/secret", nil)
		if code == 503 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if code != 503 || body["reason"] != "temporarily_unavailable" {
		t.Fatalf("protected during outage → %d %v", code, body)
	}
	if code, _ := p.JSON(http.MethodGet, "/api/v1/session", nil); code != 503 && code != 404 {
		t.Fatalf("auth routes during outage → %d", code)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
