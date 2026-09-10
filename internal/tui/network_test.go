package tui

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshconfig"
	"github.com/armtch-dev/clavis/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

func silentEndpoint(t *testing.T) (string, int, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		close(accepted)
		io.Copy(io.Discard, c)
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port, accepted
}

func TestCloseCancelsStartedSSHWork(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		m := newTestModel(t)
		p := addPasswordProfile(t, m, "loopback")
		host, port, accepted := silentEndpoint(t)
		p.Host, p.Port = host, port
		cmd := m.testCmd(*p)
		if preflight {
			cmd = m.startConnect(*p)
		}
		done := make(chan struct{})
		go func() { cmd(); close(done) }()
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("SSH work never started")
		}
		start := time.Now()
		m.Close()
		select {
		case <-done:
		case <-time.After(300 * time.Millisecond):
			t.Fatal("Close abandoned SSH work")
		}
		if time.Since(start) > 300*time.Millisecond {
			t.Fatal("Close waited for SSH timeout")
		}
	}
}

func TestWizardEscapeCancelsTestAndQueuedTrust(t *testing.T) {
	m := newTestModel(t)
	p := addPasswordProfile(t, m, "draft")
	host, port, accepted := silentEndpoint(t)
	p.Host, p.Port = host, port
	w := newWizard(m, p)
	m.wizard, m.screen = w, scrWizard
	w.usePassword, w.password = true, "hunter2"
	cmd := w.startTest(m)
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("test never started")
	}
	m.updateWizard(tea.KeyMsg{Type: tea.KeyEsc})
	select {
	case msg := <-done:
		m.dispatch(msg)
	case <-time.After(300 * time.Millisecond):
		t.Fatal("abandoned wizard test still running")
	}
	if m.store.ByID(p.ID).HostKeyFP != "" {
		t.Fatal("abandoned draft pinned live profile")
	}
}

func TestQueuedProbeCannotOverwriteRetarget(t *testing.T) {
	m := newTestModel(t)
	p := addPasswordProfile(t, m, "probe")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a := ln.Addr().(*net.TCPAddr)
	p.Host, p.Port = a.IP.String(), a.Port
	m.syncTargets()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	var msg probeMsg
	select {
	case s := <-m.probeCh:
		msg = probeMsg(s)
	case <-time.After(4 * time.Second):
		t.Fatal("no probe")
	}
	p.Host = "127.0.0.2"
	m.syncTargets()
	m.dispatch(msg)
	if _, ok := m.statuses[p.ID]; ok {
		t.Fatal("queued old endpoint result survived replacement")
	}
}

func TestTUIImportPublishesAtomicReloadedStore(t *testing.T) {
	m := newTestModel(t)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("synthetic-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.importSSHEntries([]sshconfig.Entry{{Alias: "imported", HostName: "localhost", Port: 22, User: "Deploy", IdentityFile: key}}); err != nil {
		t.Fatal(err)
	}
	p := m.store.ByName("imported")
	if p == nil {
		t.Fatal("import not published")
	}
	if raw, err := m.vault.Get(p.KeySecret()); err != nil || string(raw) != "synthetic-key" {
		t.Fatalf("imported key: %q %v", raw, err)
	}
	if err := m.store.Save(); err != nil {
		t.Fatalf("import published stale revision: %v", err)
	}
	disk, err := profile.LoadStore(m.cfgDir)
	if err != nil || disk.ByName("imported") == nil {
		t.Fatalf("import not persisted: %v", err)
	}
}

func TestSignalCancelsSSHAndQuitsApplication(t *testing.T) {
	if os.Getenv("CLAVIS_PHASE3_SIGNAL_FIXTURE") == "1" {
		m := newTestModel(t)
		host, port, accepted := silentEndpoint(t)
		done := make(chan error, 1)
		go func() {
			_, _, err := sshx.RunSessionContext(m.networkContext(), profile.Profile{Host: host, Port: port, User: "fixture"}, sshx.Credentials{Password: "synthetic"}, time.Minute)
			done <- err
		}()
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("SSH did not start")
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("signal did not cancel SSH")
			}
		case <-time.After(time.Second):
			t.Fatal("signal stranded SSH")
		}
		if _, ok := m.Init()().(tea.QuitMsg); !ok {
			t.Fatal("signal cancellation swallowed application quit")
		}
		m.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSignalCancelsSSHAndQuitsApplication$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CLAVIS_PHASE3_SIGNAL_FIXTURE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("signal subprocess: %v\n%s", err, out)
	}
}

func TestTUIImportFailureRetainsMetadata(t *testing.T) {
	m := newTestModel(t)
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(m.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("synthetic-key"), 0600); err != nil {
		t.Fatal(err)
	}
	// A nonregular vault directory makes the compound apply fail. Neither
	// detached metadata nor a false import success may be published.
	if err := os.Remove(filepath.Join(m.cfgDir, "vault")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.cfgDir, "vault"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	err = m.importSSHEntries([]sshconfig.Entry{{Alias: "failed", HostName: "localhost", Port: 22, User: "Deploy", IdentityFile: key}})
	if err == nil || m.store.ByName("failed") != nil {
		t.Fatalf("failed import published: %v", err)
	}
	after, err := os.ReadFile(m.store.Path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("failed import changed metadata: %v", err)
	}
}
