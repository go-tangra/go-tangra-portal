package httpapi

import (
	"sort"
	"sync"
	"time"
)

// Traffic keeps per-module counters over a sliding minute plus a bounded
// latency sample for the operations view (in memory, per gateway instance).
type Traffic struct {
	mu   sync.Mutex
	mods map[string]*modTraffic
	now  func() time.Time
}

type modTraffic struct {
	buckets [60]bucket
	lat     []time.Duration
	latPos  int
}

type bucket struct {
	sec      int64
	requests int
	refusals int
}

const latencySample = 256

// NewTraffic returns empty counters.
func NewTraffic() *Traffic { return &Traffic{mods: map[string]*modTraffic{}, now: time.Now} }

// Record counts one forwarded request; refusals are 401/403/429/503/504.
func (t *Traffic) Record(module string, status int, d time.Duration) {
	if module == "" {
		return
	}
	sec := t.now().Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.mods[module]
	if m == nil {
		m = &modTraffic{lat: make([]time.Duration, 0, latencySample)}
		t.mods[module] = m
	}
	b := &m.buckets[sec%60]
	if b.sec != sec {
		*b = bucket{sec: sec}
	}
	b.requests++
	switch status {
	case 401, 403, 429, 503, 504:
		b.refusals++
	}
	if len(m.lat) < latencySample {
		m.lat = append(m.lat, d)
	} else {
		m.lat[m.latPos] = d
		m.latPos = (m.latPos + 1) % latencySample
	}
}

// Snapshot is the last-minute view of one module.
type Snapshot struct {
	Requests1m int     `json:"requests_1m"`
	Refusals1m int     `json:"refusals_1m"`
	P95ms      float64 `json:"p95_ms"`
}

// Snapshot returns the counters for a module.
func (t *Traffic) Snapshot(module string) Snapshot {
	now := t.now().Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.mods[module]
	if m == nil {
		return Snapshot{}
	}
	var s Snapshot
	for _, b := range m.buckets {
		if now-b.sec < 60 {
			s.Requests1m += b.requests
			s.Refusals1m += b.refusals
		}
	}
	if len(m.lat) > 0 {
		sorted := append([]time.Duration(nil), m.lat...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		idx := (len(sorted)*95 + 99) / 100
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		s.P95ms = float64(sorted[idx].Microseconds()) / 1000
	}
	return s
}
