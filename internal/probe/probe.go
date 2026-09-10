// Package probe monitors TCP reachability with shared address-level probes.
package probe

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const historySize = 30
const maxConcurrent = 16

type Target struct {
	ProfileID string
	Addr      string
}

type Status struct {
	ProfileID  string
	Addr       string // actual probed address; retained in queued UI messages
	Generation uint64 // target incarnation, including removal/re-add at the same address
	Reachable  bool
	LatencyMs  float64
	LastSeen   time.Time
	CheckedAt  time.Time
	History    []float64
	Err        string
}

type profileState struct {
	target     Target
	generation uint64
}

type addressState struct {
	addr         string
	ctx          context.Context
	cancel       context.CancelFunc
	kick         chan struct{}
	activeCancel context.CancelFunc
	fails        int
}

// Monitor is safe for concurrent use. notify must return promptly and must not
// call SetTargets, Suspend or Stop (Snapshot/Current are safe). Delivery is
// serialized with target changes so removed work cannot publish late callbacks.
type Monitor struct {
	interval, timeout time.Duration
	notify            func(Status)
	delivery          sync.Mutex
	mu                sync.Mutex
	states            map[string]*profileState
	addresses         map[string]*addressState
	last              map[string]Status
	owners            map[string]string // session owner ID -> captured address
	sem               chan struct{}
	wg                sync.WaitGroup
	stopped           bool
	generation        uint64
}

func New(interval, timeout time.Duration, notify func(Status)) *Monitor {
	return &Monitor{interval: interval, timeout: timeout, notify: notify,
		states: make(map[string]*profileState), addresses: make(map[string]*addressState),
		last: make(map[string]Status), owners: make(map[string]string), sem: make(chan struct{}, maxConcurrent)}
}

func (m *Monitor) SetTargets(targets []Target) {
	m.delivery.Lock()
	defer m.delivery.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	wanted := make(map[string]Target, len(targets))
	for _, t := range targets {
		wanted[t.ProfileID] = t
	}
	for id, st := range m.states {
		if t, ok := wanted[id]; !ok || t.Addr != st.target.Addr {
			delete(m.states, id)
			delete(m.last, id)
		}
	}
	for id, t := range wanted {
		if m.states[id] == nil {
			m.generation++
			m.states[id] = &profileState{target: t, generation: m.generation}
		}
	}
	addrs := make(map[string]bool)
	for _, st := range m.states {
		addrs[st.target.Addr] = true
	}
	for addr, st := range m.addresses {
		if !addrs[addr] {
			st.cancel()
			delete(m.addresses, addr)
		}
	}
	for addr := range addrs {
		if m.addresses[addr] != nil {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		st := &addressState{addr: addr, ctx: ctx, cancel: cancel, kick: make(chan struct{}, 1)}
		m.addresses[addr] = st
		m.wg.Add(1)
		go m.run(st)
	}
}

func (m *Monitor) Snapshot() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.last))
	for id, s := range m.last {
		s.History = append([]float64(nil), s.History...)
		out[id] = s
	}
	return out
}

// Current lets consumers reject already-queued callbacks after target changes.
func (m *Monitor) Current(s Status) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.states[s.ProfileID]
	return st != nil && st.target.Addr == s.Addr && st.generation == s.Generation
}

func (m *Monitor) suspended(addr string) bool {
	for _, owned := range m.owners {
		if owned == addr {
			return true
		}
	}
	return false
}

func (m *Monitor) kick(st *addressState) {
	select {
	case st.kick <- struct{}{}:
	default:
	}
}

// Any profile owning an address pauses all its siblings, including in-flight
// banner reads. Each profile retains its own suspension until explicitly resumed.
func (m *Monitor) Suspend(id string, on bool) {
	m.delivery.Lock()
	defer m.delivery.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	addr, owned := m.owners[id]
	if owned == on {
		return
	}
	if on {
		p := m.states[id]
		if p == nil {
			return
		}
		addr = p.target.Addr
		m.owners[id] = addr
	} else {
		delete(m.owners, id)
	}
	st := m.addresses[addr]
	if st == nil {
		return
	}
	if on && st.activeCancel != nil {
		st.activeCancel()
	}
	if !m.suspended(st.addr) {
		m.kick(st)
	}
}

// Stop is terminal and idempotent: SetTargets after Stop does not restart work.
func (m *Monitor) Stop() {
	m.delivery.Lock()
	m.mu.Lock()
	m.stopped = true
	for _, st := range m.addresses {
		st.cancel()
	}
	clear(m.states)
	clear(m.addresses)
	clear(m.last)
	clear(m.owners)
	m.mu.Unlock()
	m.delivery.Unlock()
	m.wg.Wait()
}

func (m *Monitor) run(st *addressState) {
	defer m.wg.Done()
	timer := time.NewTimer(time.Duration(rand.Int63n(int64(max(m.interval, 0))/5 + 1)))
	defer timer.Stop()
	for {
		select {
		case <-st.ctx.Done():
			return
		case <-timer.C:
		case <-st.kick:
		}
		m.probeAndReport(st)
		m.mu.Lock()
		fails := st.fails
		m.mu.Unlock()
		timer.Reset(backoff(m.interval, fails))
	}
}

func (m *Monitor) probeAndReport(st *addressState) {
	// Queuing is cancellable, and the permit covers both dial and banner read.
	select {
	case m.sem <- struct{}{}:
	case <-st.ctx.Done():
		return
	}
	defer func() { <-m.sem }()
	m.mu.Lock()
	if m.addresses[st.addr] != st || m.suspended(st.addr) {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(st.ctx, m.timeout)
	st.activeCancel = cancel
	// Only profiles present at the start receive this observation.
	members := make(map[string]*profileState)
	for id, p := range m.states {
		if p.target.Addr == st.addr {
			members[id] = p
		}
	}
	m.mu.Unlock()
	defer cancel()
	checked := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", st.addr)
	elapsed := time.Since(checked)
	if err == nil {
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		deadline, _ := ctx.Deadline()
		conn.SetDeadline(deadline)
		fmt.Fprint(conn, "SSH-2.0-clavis_probe\r\n")
		var buf [256]byte
		conn.Read(buf[:]) // best-effort banner; reachability means TCP
		conn.Close()
		stop()
	}
	m.delivery.Lock()
	defer m.delivery.Unlock()
	m.mu.Lock()
	st.activeCancel = nil
	if m.addresses[st.addr] != st || m.suspended(st.addr) || errors.Is(ctx.Err(), context.Canceled) {
		m.mu.Unlock()
		return
	}
	if err == nil {
		st.fails = 0
	} else {
		st.fails++
	}
	var results []Status
	for id, p := range members {
		if m.states[id] != p {
			continue
		}
		s := m.last[id]
		s.ProfileID, s.Addr, s.Generation = id, st.addr, p.generation
		s.CheckedAt, s.Reachable, s.Err, s.LatencyMs = checked, err == nil, "", 0
		v := -1.0
		if err == nil {
			v = float64(elapsed) / float64(time.Millisecond)
			s.LatencyMs = v
			s.LastSeen = checked
		} else {
			s.Err = classifyErr(err)
		}
		s.History = appendHistory(s.History, v)
		m.last[id] = s
		s.History = append([]float64(nil), s.History...)
		results = append(results, s)
	}
	m.mu.Unlock()
	for _, s := range results {
		if m.notify != nil {
			m.notify(s)
		}
	}
}

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

func appendHistory(history []float64, v float64) []float64 {
	history = append(history, v)
	if len(history) > historySize {
		history = history[len(history)-historySize:]
	}
	return history
}

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
