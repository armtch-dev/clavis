package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/fido2"
	tea "github.com/charmbracelet/bubbletea"
)

// Hardware moved to commands must not hold shutdown open or publish an
// enrollment after cancellation. Only fake tools and a temporary vault run.
func TestPhase5CloseCancelsHardwareBeforePublication(t *testing.T) {
	dir := installFido2Fakes(t)
	started := filepath.Join(dir, "started")
	writeFakeTool(t, dir, "fido2-token", "#!/bin/sh\ntouch '"+started+"'\nexec sleep 30\n")
	m := newTestModel(t)
	id, err := m.vault.Identity()
	if err != nil {
		t.Fatal(err)
	}
	cmd := m.hardwareCmd(&hardwareRequest{action: "enroll"}, id)
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fake hardware never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on hardware")
	}
	result := (<-done).(hardwareDoneMsg)
	if result.err == nil || fido2.Enrolled(m.cfgDir) {
		t.Fatal("canceled hardware succeeded or published enrollment")
	}
}
