package grpcweb

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/go-freya/freya/identity"
	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcproxy"
	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcproxy/echov1"
	tgrpc "github.com/go-freya/freya/transport/grpc"
)

type director struct {
	route grpcproxy.Route
	err   error
	md    metadata.MD
}

func (d *director) Direct(_ context.Context, _ string, md metadata.MD) (grpcproxy.Route, error) {
	d.md = md
	return d.route, d.err
}

func newBridge(t *testing.T) (*Bridge, *director, *echov1.Server) {
	t.Helper()
	ca := testutil.MustCA("example.org")
	modRT := testrt.New(t, ca, "orders")
	gs, _ := tgrpc.NewServer(modRT, tgrpc.WithAddress("127.0.0.1:0"))
	echo := &echov1.Server{}
	echov1.RegisterEchoServer(gs, echo)
	stop := testrt.StartServer(t, gs)
	t.Cleanup(stop)
	ep, _ := gs.Endpoint()
	orders, _ := identity.NewSPIFFEID("example.org", "orders")
	d := &director{route: grpcproxy.Route{Module: "orders", Identity: orders, Target: ep.Host, Token: "platform", MaxDuration: 2 * time.Second, Subjects: []string{"user:u1"}}}
	p, err := grpcproxy.New(testrt.New(t, ca, "gateway"), grpcproxy.Options{Director: d})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return &Bridge{Proxy: p, MaxFrame: 1 << 16}, d, echo
}

func call(t *testing.T, b *Bridge, ct, method string, msgs ...proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	for _, m := range msgs {
		raw, _ := proto.Marshal(m)
		body.Write(EncodeFrame(FlagData, raw))
	}
	payload := body.Bytes()
	if strings.HasPrefix(ct, "application/grpc-web-text") {
		payload = []byte(base64.StdEncoding.EncodeToString(payload))
	}
	req := httptest.NewRequest(http.MethodPost, "https://platform"+method, bytes.NewReader(payload))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Grpc-Web", "1")
	req.Header.Set("Authorization", "Bearer client")
	req.Header.Set("Cookie", "__Host-session=abc")
	req.Header.Set("X-Custom", "keep")
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, text bool) ([]*echov1.Msg, metadata.MD) {
	t.Helper()
	frames, trailers, err := DecodeResponse(rec.Body.Bytes(), text)
	if err != nil {
		t.Fatal(err)
	}
	var out []*echov1.Msg
	for _, f := range frames {
		var m echov1.Msg
		if err := proto.Unmarshal(f, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, &m)
	}
	return out, trailers
}

func TestUnaryAndServerStreaming(t *testing.T) {
	b, d, _ := newBridge(t)
	for _, ct := range []string{"application/grpc-web+proto", "application/grpc-web-text+proto", "application/grpc-web"} {
		text := strings.HasPrefix(ct, "application/grpc-web-text")
		rec := call(t, b, ct, "/echo.v1.Echo/Unary", &echov1.Msg{Text: "hi", Count: 1})
		if rec.Code != 200 || rec.Header().Get("Content-Type") != ct || rec.Header().Get("X-Echo-Header") != "h1" {
			t.Fatalf("%s: %d %v %s", ct, rec.Code, rec.Header(), rec.Body.String())
		}
		msgs, trailers := decode(t, rec, text)
		if len(msgs) != 1 || msgs[0].Count != 2 || !strings.Contains(msgs[0].Text, "authorization=Bearer platform") || strings.Contains(msgs[0].Text, "cookie=") || !strings.Contains(msgs[0].Text, "x-custom=keep") {
			t.Fatalf("%s: %+v", ct, msgs)
		}
		if trailers.Get("grpc-status")[0] != "0" || trailers.Get("x-echo-trailer")[0] != "t1" {
			t.Fatalf("%s: trailers %v", ct, trailers)
		}
		// The director saw the browser credentials (cookie, authorization) but not x-grpc-web.
		if d.md.Get("cookie") == nil || d.md.Get("authorization") == nil || d.md.Get("x-grpc-web") != nil {
			t.Fatalf("director metadata %v", d.md)
		}
	}
	rec := call(t, b, "application/grpc-web+proto", "/echo.v1.Echo/ServerStream", &echov1.Msg{Text: "s", Count: 4})
	msgs, trailers := decode(t, rec, false)
	if len(msgs) != 4 || msgs[3].Count != 3 || trailers.Get("grpc-status")[0] != "0" {
		t.Fatalf("%+v %v", msgs, trailers)
	}
	// Module error → trailers-only response with the status in headers.
	rec = call(t, b, "application/grpc-web+proto", "/echo.v1.Echo/Unary", &echov1.Msg{Text: "fail"})
	if rec.Code != 200 || rec.Header().Get("Grpc-Status") != "9" || rec.Header().Get("Grpc-Message") != "module says no" || rec.Body.Len() != 0 {
		t.Fatalf("%d %v %q", rec.Code, rec.Header(), rec.Body.String())
	}
	// Empty request body → an empty message is still forwarded.
	rec = call(t, b, "application/grpc-web+proto", "/echo.v1.Echo/Unary")
	if msgs, _ := decode(t, rec, false); len(msgs) != 1 || msgs[0].Count != 1 {
		t.Fatalf("%+v", msgs)
	}
}

func TestRefusalsAndFraming(t *testing.T) {
	b, d, echo := newBridge(t)
	// Client streaming is refused.
	rec := call(t, b, "application/grpc-web+proto", "/echo.v1.Echo/ClientStream", &echov1.Msg{}, &echov1.Msg{})
	if rec.Header().Get("Grpc-Status") != "12" {
		t.Fatalf("client streaming: %v", rec.Header())
	}
	// Director refusal.
	d.err = status.Error(codes.PermissionDenied, "forbidden")
	rec = call(t, b, "application/grpc-web+proto", "/echo.v1.Echo/Unary", &echov1.Msg{})
	if rec.Header().Get("Grpc-Status") != "7" || rec.Header().Get("Grpc-Message") != "forbidden" {
		t.Fatalf("%v", rec.Header())
	}
	d.err = nil
	// Wrong method / content type.
	req := httptest.NewRequest(http.MethodGet, "https://platform/echo.v1.Echo/Unary", nil)
	rec = httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("%d", rec.Code)
	}
	// Oversized frame, truncated frame, trailer frame as request, bad base64.
	for name, body := range map[string][]byte{
		"oversized": EncodeFrame(FlagData, make([]byte, 1<<17)),
		"truncated": {0, 0, 0, 0, 9, 1, 2},
		"trailer":   EncodeFrame(FlagTrailer, []byte("grpc-status: 0")),
	} {
		req := httptest.NewRequest(http.MethodPost, "https://platform/echo.v1.Echo/Unary", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/grpc-web+proto")
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		if rec.Header().Get("Grpc-Status") != "3" {
			t.Errorf("%s: %v", name, rec.Header())
		}
	}
	req = httptest.NewRequest(http.MethodPost, "https://platform/echo.v1.Echo/Unary", strings.NewReader("!!!notbase64"))
	req.Header.Set("Content-Type", "application/grpc-web-text")
	rec = httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	if rec.Header().Get("Grpc-Status") != "3" {
		t.Fatalf("bad base64: %v", rec.Header())
	}
	// Lifetime cap on a slow server stream ends with DeadlineExceeded in the trailers frame.
	echo.Delay.Store(int64(300 * time.Millisecond))
	d.route.MaxDuration = 400 * time.Millisecond
	rec = call(t, b, "application/grpc-web+proto", "/echo.v1.Echo/ServerStream", &echov1.Msg{Text: "s", Count: 10})
	_, trailers := decode(t, rec, false)
	if trailers.Get("grpc-status") == nil || trailers.Get("grpc-status")[0] != "4" {
		t.Fatalf("%v", trailers)
	}
	echo.Delay.Store(0)
	// Framing helpers.
	if _, _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0}), 0); err != ErrTruncated {
		t.Fatal(err)
	}
	if _, _, err := DecodeResponse([]byte("%%%"), true); err == nil {
		t.Fatal("bad base64 accepted")
	}
	if _, _, err := DecodeResponse([]byte{0, 0, 0, 0, 5, 1}, false); err == nil {
		t.Fatal("truncated accepted")
	}
	md := ParseTrailers(EncodeTrailers(metadata.Pairs("B", "2", "a", "1", "a", "3")))
	if md.Get("a")[1] != "3" || md.Get("b")[0] != "2" {
		t.Fatalf("%v", md)
	}
	if !IsGRPCWeb("application/grpc-web-text+proto") || IsGRPCWeb("application/grpc") {
		t.Fatal("IsGRPCWeb")
	}
	if frameReason(io.EOF) != "malformed_frame" || frameReason(ErrFrameTooLarge) != "payload_too_large" {
		t.Fatal("reason")
	}
}
