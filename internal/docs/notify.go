package docs

import "sync"

// Notifier fans documentation changes out to subscribers (the shell's SSE
// streams). Slow subscribers miss notices rather than block the indexer.
type Notifier struct {
	mu   sync.Mutex
	subs map[chan string]struct{}
}

// Publish announces that module's documentation changed.
func (n *Notifier) Publish(module string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for ch := range n.subs {
		select {
		case ch <- module:
		default:
		}
	}
}

// Subscribe returns a channel of changed modules and its cancel function.
func (n *Notifier) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 16)
	n.mu.Lock()
	if n.subs == nil {
		n.subs = map[chan string]struct{}{}
	}
	n.subs[ch] = struct{}{}
	n.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			n.mu.Lock()
			delete(n.subs, ch)
			n.mu.Unlock()
		})
	}
}
