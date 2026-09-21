package health

import "time"

// Circuit is the per-instance breaker: closed (healthy) → open after N
// consecutive failures (unhealthy, not probed during the cool-down) →
// half-open (one probe after the cool-down) → closed on success.
type Circuit struct {
	Threshold int
	Cooldown  time.Duration
	failures  int
	open      bool
	openUntil time.Time
}

// Open reports whether the breaker is open (instance unhealthy).
func (c *Circuit) Open() bool { return c.open }

// ShouldProbe reports whether a probe is due at now (closed: always;
// open: only once the cool-down elapsed, i.e. half-open).
func (c *Circuit) ShouldProbe(now time.Time) bool {
	return !c.open || !now.Before(c.openUntil)
}

// Observe records an outcome and reports whether the state flipped.
func (c *Circuit) Observe(ok bool, now time.Time) (flipped bool) {
	if ok {
		c.failures = 0
		if c.open {
			c.open = false
			return true
		}
		return false
	}
	c.failures++
	if c.open {
		c.openUntil = now.Add(c.Cooldown) // a failed half-open probe re-arms the cool-down
		return false
	}
	if c.failures >= c.Threshold {
		c.open = true
		c.openUntil = now.Add(c.Cooldown)
		return true
	}
	return false
}
