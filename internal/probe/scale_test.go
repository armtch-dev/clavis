package probe

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func countingListener(t *testing.T, silent bool) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	count := new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if !silent {
					fmt.Fprint(conn, "SSH-2.0-fixture\r\n")
				}
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String(), count
}

func TestDuplicateAddressesShareNetworkAndSuspension(t *testing.T) {
	addr, count := countingListener(t, false)
	c := &notifyCollector{}
	m := New(100*time.Millisecond, time.Second, c.notify)
	defer m.Stop()
	m.SetTargets([]Target{{"a", addr}, {"b", addr}})
	waitFor(t, func() bool { return len(m.Snapshot()) == 2 }, "both profiles")
	s := m.Snapshot()
	if !s["a"].CheckedAt.Equal(s["b"].CheckedAt) || count.Load() != 1 {
		t.Fatalf("duplicate network work: %d, %+v", count.Load(), s)
	}
	m.Suspend("a", true)
	before := count.Load()
	time.Sleep(350 * time.Millisecond)
	if count.Load() != before {
		t.Fatal("sibling probed a session-owned address")
	}
	m.Suspend("b", true)
	m.Suspend("a", false)
	time.Sleep(250 * time.Millisecond)
	if count.Load() != before {
		t.Fatal("one resume discarded another profile's suspension")
	}
	m.Suspend("b", false)
	waitFor(t, func() bool { return count.Load() > before }, "resume")
}

func TestStopCancelsSilentBanner(t *testing.T) {
	addr, count := countingListener(t, true)
	m := New(time.Millisecond, time.Minute, func(Status) {})
	m.SetTargets([]Target{{"a", addr}})
	waitFor(t, func() bool { return count.Load() == 1 }, "active silent probe")
	start := time.Now()
	m.Stop()
	if time.Since(start) > 250*time.Millisecond {
		t.Fatalf("Stop waited for network timeout: %v", time.Since(start))
	}
	m.Stop()
}

func TestNetworkConcurrencyIsBounded(t *testing.T) {
	var targets []Target
	var counts []*atomic.Int32
	for i := range 64 {
		addr, count := countingListener(t, true)
		counts = append(counts, count)
		targets = append(targets, Target{fmt.Sprint(i), addr})
	}
	m := New(time.Millisecond, time.Minute, func(Status) {})
	defer m.Stop()
	m.SetTargets(targets)
	time.Sleep(150 * time.Millisecond)
	var active int32
	for _, c := range counts {
		active += c.Load()
	}
	if active < 2 || active > 16 {
		t.Fatalf("expected bounded parallel probes (2..16), got %d", active)
	}
}

func TestRetargetDiscardsInFlightAndHistory(t *testing.T) {
	old, count := countingListener(t, true)
	newAddr, _ := countingListener(t, false)
	c := &notifyCollector{}
	m := New(time.Millisecond, time.Second, c.notify)
	defer m.Stop()
	m.SetTargets([]Target{{"a", old}})
	waitFor(t, func() bool { return count.Load() == 1 }, "old in flight")
	m.SetTargets([]Target{{"a", newAddr}})
	waitFor(t, func() bool { return len(m.Snapshot()) == 1 }, "replacement")
	m.SetTargets(nil)
	after := c.count()
	time.Sleep(100 * time.Millisecond)
	if len(m.Snapshot()) != 0 || c.count() != after {
		t.Fatal("removed/retargeted work resurrected status")
	}
}

func TestSessionOwnershipSurvivesProfileReplacement(t *testing.T) {
	addr, count := countingListener(t, false)
	other, _ := countingListener(t, false)
	m := New(20*time.Millisecond, time.Second, func(Status) {})
	defer m.Stop()
	m.SetTargets([]Target{{"owner", addr}, {"sibling", addr}})
	waitFor(t, func() bool { return len(m.Snapshot()) == 2 }, "first shared observation")
	m.Suspend("owner", true)
	before := count.Load()
	m.SetTargets([]Target{{"owner", other}, {"sibling", addr}})
	time.Sleep(100 * time.Millisecond)
	if count.Load() != before {
		t.Fatal("retarget released live session's old address")
	}
	m.SetTargets([]Target{{"sibling", addr}})
	time.Sleep(100 * time.Millisecond)
	if count.Load() != before {
		t.Fatal("removal released live session's old address")
	}
	m.Suspend("owner", false)
	waitFor(t, func() bool { return count.Load() > before }, "old address released after logout")
}
