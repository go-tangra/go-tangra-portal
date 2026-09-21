package grpcweb

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcproxy"
)

// Opener starts forwarded streams (the passthrough proxy).
type Opener interface {
	Open(ctx context.Context, fullMethod string, md metadata.MD) (*grpcproxy.Stream, error)
}

// Bridge translates gRPC-web to gRPC.
type Bridge struct {
	Proxy    Opener
	MaxFrame int   // default 4 MiB
	MaxBody  int64 // request body cap, default 4 MiB + framing
}

// IsGRPCWeb reports whether a request carries gRPC-web content.
func IsGRPCWeb(contentType string) bool {
	return strings.HasPrefix(contentType, "application/grpc-web")
}

// request metadata never forwarded to the director/module.
var droppedHeaders = map[string]bool{"content-type": true, "content-length": true, "x-grpc-web": true, "x-user-agent": true, "accept": true, "accept-encoding": true, "connection": true, "host": true, "origin": true, "referer": true, "sec-fetch-site": true, "sec-fetch-mode": true, "sec-fetch-dest": true, "x-csrf-token": true}

// ServeHTTP handles one gRPC-web call.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if r.Method != http.MethodPost || !IsGRPCWeb(ct) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_, _ = w.Write([]byte(`{"reason":"validation_failed"}`))
		return
	}
	maxFrame := b.MaxFrame
	if maxFrame <= 0 {
		maxFrame = 4 << 20
	}
	maxBody := b.MaxBody
	if maxBody <= 0 {
		maxBody = int64(maxFrame) + 64
	}
	text := strings.HasPrefix(ct, "application/grpc-web-text")
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxBody)
	if text {
		body = base64.NewDecoder(base64.StdEncoding, body)
	}
	md := metadata.MD{}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if droppedHeaders[lk] {
			continue
		}
		md[lk] = append([]string(nil), vs...)
	}
	if deadline := r.Header.Get("grpc-timeout"); deadline != "" {
		md.Set("grpc-timeout", deadline)
	}
	// One request message at most: gRPC-web has no client streaming.
	flag, payload, err := ReadFrame(body, maxFrame)
	if err != nil && !errors.Is(err, io.EOF) {
		b.trailersOnly(w, ct, text, status.New(codes.InvalidArgument, frameReason(err)), nil)
		return
	}
	if err == nil {
		if flag != FlagData {
			b.trailersOnly(w, ct, text, status.New(codes.InvalidArgument, "unexpected trailer frame"), nil)
			return
		}
		if _, _, more := ReadFrame(body, maxFrame); !errors.Is(more, io.EOF) {
			b.trailersOnly(w, ct, text, status.New(codes.Unimplemented, "client streaming is not supported over gRPC-web"), nil)
			return
		}
	} else {
		payload = nil
	}
	st, err := b.Proxy.Open(r.Context(), r.URL.Path, md)
	if err != nil {
		b.trailersOnly(w, ct, text, status.Convert(err), nil)
		return
	}
	defer st.Done(nil)
	if err := st.SendMsg(&grpcproxy.Frame{Data: payload}); err != nil {
		b.trailersOnly(w, ct, text, status.Convert(err), nil)
		st.Done(err)
		return
	}
	_ = st.CloseSend()
	flusher, _ := w.(http.Flusher)
	headersSent := false
	for {
		var f grpcproxy.Frame
		rerr := st.RecvMsg(&f)
		if rerr != nil {
			stat := status.Convert(rerr)
			if errors.Is(rerr, io.EOF) {
				stat = status.New(codes.OK, "")
			}
			if st.Revoked() && (stat.Code() == codes.Canceled || stat.Code() == codes.DeadlineExceeded) {
				stat = status.New(codes.PermissionDenied, "forbidden")
			}
			trailer := st.Trailer()
			if !headersSent {
				hdr, _ := st.Header()
				b.trailersOnly(w, ct, text, stat, joinMD(hdr, trailer))
				st.Done(rerr)
				return
			}
			_, _ = w.Write(b.frame(text, FlagTrailer, EncodeTrailers(statusMD(stat, trailer))))
			if flusher != nil {
				flusher.Flush()
			}
			st.Done(rerr)
			return
		}
		if !headersSent {
			hdr, _ := st.Header()
			for k, vs := range hdr {
				if strings.HasPrefix(k, "grpc-") {
					continue
				}
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			headersSent = true
		}
		_, _ = w.Write(b.frame(text, FlagData, f.Data))
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func frameReason(err error) string {
	switch {
	case errors.Is(err, ErrFrameTooLarge):
		return "payload_too_large"
	default:
		return "malformed_frame"
	}
}

func (b *Bridge) frame(text bool, flag byte, payload []byte) []byte {
	raw := EncodeFrame(flag, payload)
	if !text {
		return raw
	}
	return []byte(base64.StdEncoding.EncodeToString(raw))
}

// trailersOnly answers with the status in HTTP headers and an empty body.
func (b *Bridge) trailersOnly(w http.ResponseWriter, ct string, _ bool, st *status.Status, md metadata.MD) {
	for k, vs := range md {
		if strings.HasPrefix(k, "grpc-") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Grpc-Status", strconv.Itoa(int(st.Code())))
	w.Header().Set("Grpc-Message", st.Message())
	w.WriteHeader(http.StatusOK)
}

func statusMD(st *status.Status, trailer metadata.MD) metadata.MD {
	md := metadata.MD{}
	for k, v := range trailer {
		if !strings.HasPrefix(k, "grpc-") {
			md[k] = v
		}
	}
	md.Set("grpc-status", strconv.Itoa(int(st.Code())))
	if st.Message() != "" {
		md.Set("grpc-message", st.Message())
	}
	return md
}

func joinMD(a, b metadata.MD) metadata.MD {
	out := metadata.MD{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = append(out[k], v...)
	}
	return out
}

// DecodeResponse splits a binary gRPC-web response body into data frames and
// trailers (client helper for tests and the shell's contract checks).
func DecodeResponse(body []byte, text bool) (frames [][]byte, trailers metadata.MD, err error) {
	if text {
		// Text responses carry one padded base64 string per frame, concatenated.
		var raw []byte
		rest := string(body)
		for rest != "" {
			end := len(rest)
			if i := strings.IndexByte(rest, '='); i >= 0 {
				end = i
				for end < len(rest) && rest[end] == '=' {
					end++
				}
			}
			chunk, err := base64.StdEncoding.DecodeString(rest[:end])
			if err != nil {
				return nil, nil, err
			}
			raw = append(raw, chunk...)
			rest = rest[end:]
		}
		body = raw
	}
	rd := bytes.NewReader(body)
	for {
		flag, payload, err := ReadFrame(rd, 0)
		if errors.Is(err, io.EOF) {
			return frames, trailers, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if flag == FlagTrailer {
			trailers = ParseTrailers(payload)
			continue
		}
		frames = append(frames, payload)
	}
}
