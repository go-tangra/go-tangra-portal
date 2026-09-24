package registry

// Event kinds carried by gateway.v1.RegistryEvent.kind and the shell SSE feed.
const (
	EventRegistered = "registered"
	EventUpdated    = "updated"
	EventWithdrawn  = "withdrawn"
	EventDrained    = "drained"
	EventRevoked    = "revoked"
	EventUnhealthy  = "unhealthy"
	EventRecovered  = "recovered"
)

// EventKinds is the closed vocabulary, in contract order.
var EventKinds = []string{EventRegistered, EventUpdated, EventWithdrawn, EventDrained, EventRevoked, EventUnhealthy, EventRecovered}

// KnownEvent reports whether k is in the vocabulary.
func KnownEvent(k string) bool {
	for _, e := range EventKinds {
		if e == k {
			return true
		}
	}
	return false
}
