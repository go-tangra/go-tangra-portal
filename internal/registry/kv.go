package registry

import (
	"context"
	"sync"
	"time"
)

// KV is the key-value surface the registry needs; implemented by Valkey
// (registrydb) and by the in-memory fake below.
type KV interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Keys(ctx context.Context, prefix string) ([]string, error)
	Publish(ctx context.Context, channel, msg string) error
	Subscribe(ctx context.Context, channel string, onMessage func(string)) error
	Close()
}

// Keys (data-model.md).
const (
	Channel    = "gateway:registry"
	regPrefix  = "reg:"
	leasePfx   = "lease:"
	leaseIdx   = "leaseid:"
	versionKey = "reg:version"
)

func regKey(module string) string             { return regPrefix + module }
func leaseKey(module, instance string) string { return leasePfx + module + ":" + instance }
func leaseIndexKey(lease string) string       { return leaseIdx + lease }

// Memory is an in-memory KV for tests and single-process development.
type Memory struct {
	mu   sync.Mutex
	data map[string]entry
	subs map[string][]func(string)
	// Now is the clock used for TTLs (tests).
	Now func() time.Time
	// Fail, when set, is returned by every operation (failure injection).
	Fail error
}

type entry struct {
	v   string
	exp time.Time
}

// NewMemory returns an empty in-memory KV.
func NewMemory() *Memory {
	return &Memory{data: map[string]entry{}, subs: map[string][]func(string){}, Now: time.Now}
}

func (m *Memory) live(k string) (entry, bool) {
	e, ok := m.data[k]
	if !ok {
		return entry{}, false
	}
	if !e.exp.IsZero() && !m.Now().Before(e.exp) {
		m.evict(k)
		return entry{}, false
	}
	return e, true
}

func (m *Memory) evict(k string) {
	next := make(map[string]entry, len(m.data))
	for kk, v := range m.data {
		if kk != k {
			next[kk] = v
		}
	}
	m.data = next
}

// Get implements KV.
func (m *Memory) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return "", false, m.Fail
	}
	e, ok := m.live(key)
	return e.v, ok, nil
}

// Set implements KV.
func (m *Memory) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	e := entry{v: value}
	if ttl > 0 {
		e.exp = m.Now().Add(ttl)
	}
	m.data[key] = e
	return nil
}

// Del implements KV.
func (m *Memory) Del(_ context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, k := range keys {
		m.evict(k)
	}
	return nil
}

// Incr implements KV.
func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, m.Fail
	}
	e, ok := m.live(key)
	var n int64
	if ok {
		for _, ch := range e.v {
			n = n*10 + int64(ch-'0')
		}
	}
	n++
	ne := entry{v: itoa(n), exp: e.exp}
	if !ok && ttl > 0 {
		ne.exp = m.Now().Add(ttl)
	}
	m.data[key] = ne
	return n, nil
}

// Keys implements KV (live keys with the prefix, unordered).
func (m *Memory) Keys(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var out []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			if _, ok := m.live(k); ok {
				out = append(out, k)
			}
		}
	}
	return out, nil
}

// Publish implements KV.
func (m *Memory) Publish(_ context.Context, channel, msg string) error {
	m.mu.Lock()
	if m.Fail != nil {
		m.mu.Unlock()
		return m.Fail
	}
	subs := append([]func(string){}, m.subs[channel]...)
	m.mu.Unlock()
	for _, s := range subs {
		s(msg)
	}
	return nil
}

// Subscribe implements KV; it blocks until ctx ends.
func (m *Memory) Subscribe(ctx context.Context, channel string, onMessage func(string)) error {
	m.mu.Lock()
	m.subs[channel] = append(m.subs[channel], onMessage)
	m.mu.Unlock()
	<-ctx.Done()
	return nil
}

// Close implements KV.
func (m *Memory) Close() {}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
