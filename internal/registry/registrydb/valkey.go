// Package registrydb binds the registry KV to Valkey (TLS 1.3 unless
// explicitly allowed otherwise). Covered by the integration suite.
package registrydb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	valkey "github.com/valkey-io/valkey-go"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

// Config connects to Valkey.
type Config struct {
	Addresses      []string
	Username       string
	Password       string
	AllowPlaintext bool
	CAPEM          []byte
}

type kv struct{ c valkey.Client }

// New returns a registry.KV backed by Valkey.
func New(cfg Config) (registry.KV, error) {
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("registrydb: valkey addresses required")
	}
	opt := valkey.ClientOption{InitAddress: cfg.Addresses, Username: cfg.Username, Password: cfg.Password}
	if !cfg.AllowPlaintext {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("registrydb: valkey ca is not valid PEM")
			}
			opt.TLSConfig.RootCAs = pool
		}
	}
	c, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("registrydb: %w", err)
	}
	return &kv{c: c}, nil
}

func (v *kv) Get(ctx context.Context, key string) (string, bool, error) {
	s, err := v.c.Do(ctx, v.c.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return s, true, nil
}

func (v *kv) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl > 0 {
		return v.c.Do(ctx, v.c.B().Set().Key(key).Value(value).Px(ttl).Build()).Error()
	}
	return v.c.Do(ctx, v.c.B().Set().Key(key).Value(value).Build()).Error()
}

func (v *kv) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return v.c.Do(ctx, v.c.B().Del().Key(keys...).Build()).Error()
}

func (v *kv) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := v.c.Do(ctx, v.c.B().Incr().Key(key).Build()).AsInt64()
	if err != nil {
		return 0, err
	}
	if n == 1 && ttl > 0 {
		_ = v.c.Do(ctx, v.c.B().Pexpire().Key(key).Milliseconds(ttl.Milliseconds()).Build()).Error()
	}
	return n, nil
}

// Keys scans for live keys with the prefix (SCAN, never KEYS).
func (v *kv) Keys(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	var cursor uint64
	for {
		res, err := v.c.Do(ctx, v.c.B().Scan().Cursor(cursor).Match(prefix+"*").Count(200).Build()).AsScanEntry()
		if err != nil {
			return nil, err
		}
		out = append(out, res.Elements...)
		cursor = res.Cursor
		if cursor == 0 {
			return out, nil
		}
	}
}

func (v *kv) Publish(ctx context.Context, channel, msg string) error {
	return v.c.Do(ctx, v.c.B().Publish().Channel(channel).Message(msg).Build()).Error()
}

func (v *kv) Subscribe(ctx context.Context, channel string, onMessage func(string)) error {
	return v.c.Receive(ctx, v.c.B().Subscribe().Channel(channel).Build(), func(m valkey.PubSubMessage) { onMessage(m.Message) })
}

func (v *kv) Close() { v.c.Close() }
