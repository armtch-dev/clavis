package tui

import (
	"context"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

type networkJob struct {
	ctx      context.Context
	cancel   context.CancelFunc
	endpoint profile.Profile
}

func (m *Model) networkContext() context.Context {
	if m.workContext != nil {
		return m.workContext
	}
	return context.Background()
}

func (m *Model) networkJob(p profile.Profile) *networkJob {
	ctx, cancel := context.WithCancel(m.networkContext())
	return &networkJob{ctx: ctx, cancel: cancel, endpoint: p}
}

func (m *Model) runTest(p profile.Profile, creds sshx.Credentials, wizard *wizardModel) tea.Cmd {
	// Wizard cancellation wipes its draft buffer while auth may still be
	// parsing. Give the worker its own bytes and wipe them when it returns.
	creds.PrivateKey = append([]byte(nil), creds.PrivateKey...)
	job := m.networkJob(p)
	if wizard != nil {
		if wizard.testJob != nil {
			wizard.testJob.cancel()
		}
		wizard.testJob = job
	} else {
		if m.sshTests == nil {
			m.sshTests = make(map[string]*networkJob)
		}
		if old := m.sshTests[p.ID]; old != nil {
			old.cancel()
		}
		m.sshTests[p.ID] = job
	}
	return m.background(func() tea.Msg {
		defer func() { clear(creds.PrivateKey); creds = sshx.Credentials{} }()
		return testDoneMsg{profileID: p.ID, endpoint: p, result: sshx.TestContext(job.ctx, p, creds, testTimeout), job: job, wizard: wizard}
	}, nil)
}

type scopedPreflightMsg struct {
	preflightMsg
	pending *pendingConnect
}

func (m *Model) preflightCmd(pc *pendingConnect) tea.Cmd {
	pc.job = m.networkJob(pc.p)
	p, job := pc.p, pc.job
	return m.background(func() tea.Msg {
		var err error
		if p.ProxyJump == "" {
			err = sshx.PreflightContext(job.ctx, p.Addr(), preflightTimeout)
		}
		return scopedPreflightMsg{preflightMsg: preflightMsg{p.ID, err}, pending: pc}
	}, nil)
}

func (m *Model) cancelPending() {
	if m.pending != nil {
		if m.pending.job != nil {
			m.pending.job.cancel()
		}
		m.monitor.Suspend(m.pending.p.ID, false)
		m.pending.creds = sshx.Credentials{}
	}
	m.pending, m.connecting = nil, ""
}

func (m *Model) cancelObsoleteNetwork() {
	for id, job := range m.sshTests {
		if p := m.store.ByID(id); p == nil || !sameTestTarget(m.effective(*p), job.endpoint) {
			job.cancel()
			delete(m.sshTests, id)
			delete(m.testing, id)
		}
	}
	if m.pending != nil && !m.currentEndpoint(m.pending.p.ID, m.pending.p) {
		m.cancelPending()
	}
}
