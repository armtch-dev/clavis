package probe

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testInterval = 50 * time.Millisecond
	testTimeout  = 500 * time.Millisecond
	waitDeadline = 2 * time.Second
	pollEvery    = 10 * time.Millisecond
)

// waitFor polls cond until it returns true or the deadline elapses, failing
// the test if the deadline is reached first.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(waitDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(pollEvery)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

type notifyCollector struct {
	mu       sync.Mutex
	statuses []Status
}

func (c *notifyCollector) notify(s Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses = append(c.statuses, s)
}

func (c *notifyCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.statuses)
}

func (c *notifyCollector) latest(profileID string) (Status, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.statuses) - 1; i >= 0; i-- {
		if c.statuses[i].ProfileID == profileID {
			return c.statuses[i], true
		}
	}
	return Status{}, false
}

func TestReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)
	defer m.Stop()

	m.SetTargets([]Target{{ProfileID: "a", Addr: ln.Addr().String()}})

	waitFor(t, func() bool {
		s, ok := c.latest("a")
		return ok && s.Reachable
	}, "reachable notify for target a")

	s, _ := c.latest("a")
	if !s.Reachable {
		t.Fatalf("expected reachable")
	}
	if s.LatencyMs < 0 {
		t.Fatalf("expected non-negative latency, got %v", s.LatencyMs)
	}
	if s.LastSeen.IsZero() {
		t.Fatalf("expected LastSeen to be set")
	}

	waitFor(t, func() bool {
		snap := m.Snapshot()
		s, ok := snap["a"]
		return ok && len(s.History) >= 2
	}, "history growing past one entry")
}

func TestUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // now addr is a closed port that will refuse connections

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)
	defer m.Stop()

	m.SetTargets([]Target{{ProfileID: "b", Addr: addr}})

	waitFor(t, func() bool {
		s, ok := c.latest("b")
		return ok && !s.Reachable
	}, "unreachable notify for target b")

	s, _ := c.latest("b")
	if s.Reachable {
		t.Fatalf("expected unreachable")
	}
	if !strings.Contains(s.Err, "refused") {
		t.Fatalf("expected Err to contain 'refused', got %q", s.Err)
	}
}

func TestSetTargetsReconciliation(t *testing.T) {
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnA.Close()
	go acceptLoop(lnA)

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnB.Close()
	go acceptLoop(lnB)

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)
	defer m.Stop()

	m.SetTargets([]Target{{ProfileID: "A", Addr: lnA.Addr().String()}})

	waitFor(t, func() bool {
		_, ok := c.latest("A")
		return ok
	}, "first notify for A")

	m.SetTargets([]Target{{ProfileID: "B", Addr: lnB.Addr().String()}})

	waitFor(t, func() bool {
		_, ok := c.latest("B")
		return ok
	}, "first notify for B")

	waitFor(t, func() bool {
		snap := m.Snapshot()
		_, hasA := snap["A"]
		_, hasB := snap["B"]
		return !hasA && hasB
	}, "snapshot contains only B")
}

func TestStopTerminates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptLoop(ln)

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)

	m.SetTargets([]Target{{ProfileID: "s", Addr: ln.Addr().String()}})

	waitFor(t, func() bool {
		return c.count() > 0
	}, "at least one notify before stop")

	m.Stop()

	countAfterStop := c.count()
	time.Sleep(3 * testInterval)
	if c.count() != countAfterStop {
		t.Fatalf("expected no notify callbacks after Stop, count went from %d to %d", countAfterStop, c.count())
	}
}

func TestHistoryCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptLoop(ln)

	c := &notifyCollector{}
	m := New(10*time.Millisecond, testTimeout, c.notify)
	defer m.Stop()

	m.SetTargets([]Target{{ProfileID: "h", Addr: ln.Addr().String()}})

	waitFor(t, func() bool {
		snap := m.Snapshot()
		s, ok := snap["h"]
		return ok && len(s.History) == historySize
	}, "history reaching cap of 30")

	// Give it more time to keep probing past the cap and verify it doesn't grow further.
	time.Sleep(200 * time.Millisecond)
	snap := m.Snapshot()
	if len(snap["h"].History) != historySize {
		t.Fatalf("expected history capped at %d, got %d", historySize, len(snap["h"].History))
	}
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}
