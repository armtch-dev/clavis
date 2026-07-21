package probe

import (
	"fmt"
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

func TestBackoff(t *testing.T) {
	iv := 15 * time.Second
	cases := []struct {
		fails int
		want  time.Duration
	}{
		{0, 15 * time.Second},
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 5 * time.Minute}, // capped
		{9, 5 * time.Minute}, // exponent capped too
	}
	for _, c := range cases {
		if got := backoff(iv, c.fails); got != c.want {
			t.Errorf("backoff(%v, %d) = %v, want %v", iv, c.fails, got, c.want)
		}
	}
}

// A failing target must be probed less and less often: hosts that drop SSH
// probes are usually rate-limiting the source, and steady re-probing is what
// keeps the block alive.
func TestFailureBackoffSlowsProbing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // probes will be refused

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)
	defer m.Stop()
	m.SetTargets([]Target{{ProfileID: "f", Addr: addr}})

	// After 3 consecutive failures the delay is interval<<3 = 400ms; without
	// backoff, 600ms would fit ~12 more probes at the 50ms test interval.
	waitFor(t, func() bool { return c.count() >= 3 }, "three failed probes")
	before := c.count()
	time.Sleep(12 * testInterval)
	if after := c.count(); after > before+2 {
		t.Fatalf("failing target still probed at full rate: %d probes in %v", after-before, 12*testInterval)
	}
}

// Suspend pauses probing without losing the target; resume kicks an
// immediate probe rather than waiting out the interval (or a backoff delay).
func TestSuspendResume(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptLoop(ln)

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)
	defer m.Stop()
	m.SetTargets([]Target{{ProfileID: "s", Addr: ln.Addr().String()}})

	waitFor(t, func() bool { return c.count() >= 1 }, "first probe")
	m.Suspend("s", true)
	// One probe may already be in flight; after it lands the count must hold.
	time.Sleep(2 * testInterval)
	frozen := c.count()
	time.Sleep(6 * testInterval)
	if got := c.count(); got != frozen {
		t.Fatalf("suspended target kept probing: %d -> %d", frozen, got)
	}

	m.Suspend("s", false)
	waitFor(t, func() bool { return c.count() > frozen }, "probe after resume")
}

// The probe must not hang up silently: it completes the SSH identification
// exchange so the server never sees the port-scanner signature that
// aggressive fail2ban filters and OpenSSH PerSourcePenalties key on.
func TestProbeSendsClientBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var got string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				fmt.Fprintf(conn, "SSH-2.0-fake\r\n")
				buf := make([]byte, 128)
				n, _ := conn.Read(buf)
				mu.Lock()
				if got == "" {
					got = string(buf[:n])
				}
				mu.Unlock()
			}(conn)
		}
	}()

	c := &notifyCollector{}
	m := New(testInterval, testTimeout, c.notify)
	defer m.Stop()
	m.SetTargets([]Target{{ProfileID: "p", Addr: ln.Addr().String()}})

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.HasPrefix(got, "SSH-2.0-clavis_probe")
	}, "client identification string received by server")
}
