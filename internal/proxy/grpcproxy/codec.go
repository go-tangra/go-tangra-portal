package grpcproxy

import "fmt"

// Frame is an opaque gRPC message payload.
type Frame struct{ Data []byte }

// rawCodec moves message bytes untouched; the proxy never decodes payloads.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	f, ok := v.(*Frame)
	if !ok {
		return nil, fmt.Errorf("grpcproxy: codec expects *Frame, got %T", v)
	}
	return f.Data, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	f, ok := v.(*Frame)
	if !ok {
		return fmt.Errorf("grpcproxy: codec expects *Frame, got %T", v)
	}
	f.Data = append([]byte(nil), data...)
	return nil
}

// Name is "proto" so application/grpc(+proto) requests negotiate normally.
func (rawCodec) Name() string { return "proto" }
