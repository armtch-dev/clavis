// Package probe implements a background TCP reachability/latency monitor
// for SSH hosts. Each target is probed on its own goroutine at a fixed
// interval; results are reported via a callback and cached for Snapshot.
package probe

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// historySize is the number of recent probe results retained per target.
const historySize = 30

// Target identifies a host to probe.
type Target struct {
	ProfileID string
	Addr      string // host:port
}

// Status is the result of the most recent probe for a target, along with
// recent history.
type Status struct {
	ProfileID string
	Reachable bool
	LatencyMs float64   // valid only when Reachable
	LastSeen  time.Time // last successful probe (zero if never)
	CheckedAt time.Time // when this probe ran
	History   []float64 // most recent last, up to 30 entries; -1 == failed probe
	Err       string    // short reason when unreachable, e.g. "connection refused", "timeout"
}

// target tracks the running state for a single probed address.
type probeState struct {
	target    Target
	stop      chan struct{}
	kick      chan struct{} // nudges the loop to probe now (e.g. on resume)
	history   []float64     // ring buffer contents in chronological order, oldest first
	lastSeen  time.Time
	fails     int  // consecutive failures, drives backoff
	suspended bool // probing paused (an interactive session owns this host)
}

// Monitor probes a set of TCP targets in the background and reports status
// via a notify callback. A Monitor is safe for concurrent use.
type Monitor struct {
	interval time.Duration
	timeout  time.Duration
	notify   func(Status)

	mu     sync.Mutex
	states map[string]*probeState // by ProfileID
	last   map[string]Status      // by ProfileID, latest reported status
	wg     sync.WaitGroup
}

// New creates a monitor. interval is the probe period (production: 10s),
// timeout the per-dial timeout (production: 3s). notify is called after every
// probe, from the probing goroutine — it must be safe for concurrent calls.
func New(interval, timeout time.Duration, notify func(Status)) *Monitor {
	return &Monitor{
		interval: interval,
		timeout:  timeout,
		notify:   notify,
		states:   make(map[string]*probeState),
		last:     make(map[string]Status),
	}
}

// SetTargets reconciles the probed set: starts goroutines for new targets,
// stops goroutines for removed ones, restarts a target whose Addr changed.
// Safe to call at any time from any goroutine.
func (m *Monitor) SetTargets(targets []Target) {
	m.mu.Lock()

	wanted := make(map[string]Target, len(targets))
	for _, t := range targets {
		wanted[t.ProfileID] = t
	}

	// Stop and remove targets that are gone or whose address changed.
	for id, st := range m.states {
		t, ok := wanted[id]
		if !ok || t.Addr != st.target.Addr {
			close(st.stop)
			delete(m.states, id)
			delete(m.last, id)
		}
	}

	// Start new targets (including ones just removed above due to Addr change).
	var toStart []Target
	for id, t := range wanted {
		if _, ok := m.states[id]; !ok {
			toStart = append(toStart, t)
		}
	}

	for _, t := range toStart {
		st := &probeState{
			target: t,
			stop:   make(chan struct{}),
			kick:   make(chan struct{}, 1),
		}
		m.states[t.ProfileID] = st
		m.wg.Add(1)
		go m.run(st)
	}

	m.mu.Unlock()
}

// Snapshot returns the latest Status for every current target (map by ProfileID).
func (m *Monitor) Snapshot() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]Status, len(m.last))
	for id, s := range m.last {
		if _, ok := m.states[id]; !ok {
			continue // removed but not yet cleaned up (shouldn't happen, defensive)
		}
		s.History = append([]float64(nil), s.History...)
		out[id] = s
	}
	return out
}

// Suspend pauses (or resumes) probing for one target without tearing down
// its goroutine or history. Used while an interactive session owns the host:
// probing it then is redundant, and some hosts sit behind gateways that
// rate-limit new SSH connections per source — extra probes during a connect
// burst are exactly what trips them. Resuming kicks an immediate probe so
// the status refreshes as soon as the session ends.
func (m *Monitor) Suspend(profileID string, on bool) {
	m.mu.Lock()
	st, ok := m.states[profileID]
	if ok && st.suspended != on {
		st.suspended = on
		if !on {
			select {
			case st.kick <- struct{}{}:
			default:
			}
		}
	}
	m.mu.Unlock()
}

// Stop terminates all probe goroutines and waits for them to exit.
func (m *Monitor) Stop() {
	m.mu.Lock()
	for _, st := range m.states {
		close(st.stop)
	}
	m.states = make(map[string]*probeState)
	m.mu.Unlock()

	m.wg.Wait()
}

// run is the per-target probing goroutine.
func (m *Monitor) run(st *probeState) {
	defer m.wg.Done()

	// Jitter the first probe so many targets don't fire simultaneously.
	jitter := time.Duration(rand.Int63n(int64(m.interval)/5 + 1))
	timer := time.NewTimer(jitter)
	defer timer.Stop()

	select {
	case <-st.stop:
		return
	case <-timer.C:
	}

	for {
		m.mu.Lock()
		suspended := st.suspended
		fails := st.fails
		m.mu.Unlock()

		if !suspended {
			m.probeAndReport(st)
			m.mu.Lock()
			fails = st.fails
			m.mu.Unlock()
		}

		wait := time.NewTimer(backoff(m.interval, fails))
		select {
		case <-st.stop:
			wait.Stop()
			return
		case <-st.kick:
			wait.Stop()
		case <-wait.C:
		}
	}
}

// backoff stretches the probe interval after consecutive failures, doubling
// per failure up to a 5-minute cap. A host that drops SSH probes is often
// rate-limiting the source (fail2ban, gateway SYN limits); hammering it every
// interval keeps the block alive — the exact failure mode backing off breaks.
func backoff(interval time.Duration, fails int) time.Duration {
	if fails <= 0 {
		return interval
	}
	if fails > 5 {
		fails = 5
	}
	d := interval << uint(fails)
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// probeAndReport performs a single probe, updates state, and invokes notify.
func (m *Monitor) probeAndReport(st *probeState) {
	checkedAt := time.Now()
	start := time.Now()
	conn, err := net.DialTimeout("tcp", st.target.Addr, m.timeout)
	elapsed := time.Since(start)

	var status Status
	m.mu.Lock()

	// The target may have been removed/replaced between scheduling and
	// running this probe; if so, don't resurrect its state.
	if cur, ok := m.states[st.target.ProfileID]; !ok || cur != st {
		m.mu.Unlock()
		return
	}

	if err == nil {
		politeClose(conn)
		latencyMs := float64(elapsed) / float64(time.Millisecond)
		st.lastSeen = checkedAt
		st.fails = 0
		st.history = appendHistory(st.history, latencyMs)
		status = Status{
			ProfileID: st.target.ProfileID,
			Reachable: true,
			LatencyMs: latencyMs,
			LastSeen:  st.lastSeen,
			CheckedAt: checkedAt,
			History:   append([]float64(nil), st.history...),
		}
	} else {
		st.fails++
		st.history = appendHistory(st.history, -1)
		status = Status{
			ProfileID: st.target.ProfileID,
			Reachable: false,
			LastSeen:  st.lastSeen,
			CheckedAt: checkedAt,
			History:   append([]float64(nil), st.history...),
			Err:       classifyErr(err),
		}
	}

	m.last[st.target.ProfileID] = status
	m.mu.Unlock()

	m.notify(status)
}

// politeClose completes the SSH identification exchange before hanging up.
// A bare connect-then-close makes sshd log "did not receive identification
// string" — the signature port scanners leave, and what aggressive fail2ban
// filters and OpenSSH 9.8+ PerSourcePenalties key on. Sending a client
// banner and draining the server's costs one round-trip and keeps the probe
// indistinguishable from a well-behaved client that changed its mind.
func politeClose(conn net.Conn) {
	deadline := time.Now().Add(2 * time.Second)
	conn.SetDeadline(deadline)
	fmt.Fprintf(conn, "SSH-2.0-clavis_probe\r\n")
	buf := make([]byte, 256)
	conn.Read(buf) // best-effort drain of the server banner
	conn.Close()
}

// appendHistory appends v to history, capping the length at historySize by
// dropping the oldest entries.
func appendHistory(history []float64, v float64) []float64 {
	history = append(history, v)
	if len(history) > historySize {
		history = history[len(history)-historySize:]
	}
	return history
}

// classifyErr turns a dial error into a short human-readable reason.
func classifyErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "timeout"
		}
		return "dns lookup failed"
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection refused"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	if os.IsTimeout(err) {
		return "timeout"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err.Error()
	}

	return err.Error()
}
