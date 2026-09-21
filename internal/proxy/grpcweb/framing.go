// Package grpcweb bridges gRPC-web (binary and text) requests from browsers
// to the passthrough proxy: unary and server-streaming calls; client
// streaming is refused as the protocol cannot carry it.
package grpcweb

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"

	"google.golang.org/grpc/metadata"
)

// Frame flags.
const (
	FlagData    byte = 0x00
	FlagTrailer byte = 0x80
)

// Errors of the framing decoder.
var (
	ErrFrameTooLarge = errors.New("grpcweb: frame too large")
	ErrTruncated     = errors.New("grpcweb: truncated frame")
)

// EncodeFrame prefixes payload with the 5-byte gRPC-web header.
func EncodeFrame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload))) // #nosec G115 -- bounded by max frame
	copy(out[5:], payload)
	return out
}

// ReadFrame reads one frame; io.EOF at a frame boundary means no more frames.
func ReadFrame(r io.Reader, max int) (byte, []byte, error) {
	var hdr [5]byte
	n, err := io.ReadFull(r, hdr[:])
	if n == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return 0, nil, io.EOF
	}
	if err != nil {
		return 0, nil, ErrTruncated
	}
	size := binary.BigEndian.Uint32(hdr[1:5])
	if max > 0 && size > uint32(max) { // #nosec G115 -- max is a positive limit
		return 0, nil, ErrFrameTooLarge
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, ErrTruncated
	}
	return hdr[0], payload, nil
}

// EncodeTrailers renders the trailers frame body ("key: value\r\n" lines).
func EncodeTrailers(md metadata.MD) []byte {
	keys := make([]string, 0, len(md))
	for k := range md {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range md[k] {
			b.WriteString(strings.ToLower(k))
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return []byte(b.String())
}

// ParseTrailers parses a trailers frame body (used by tests and clients).
func ParseTrailers(body []byte) metadata.MD {
	md := metadata.MD{}
	for _, line := range strings.Split(string(body), "\r\n") {
		k, v, ok := strings.Cut(line, ": ")
		if ok && k != "" {
			md.Append(strings.ToLower(k), v)
		}
	}
	return md
}
