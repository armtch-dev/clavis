package tui

import (
	"fmt"
	"slices"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/charmbracelet/bubbles/textinput"
)

type trustReview struct {
	endpoint             profile.Profile
	oldFP, newFP, newKey string
	wizard               *wizardModel
	check                func(*fstxn.Lock) error
	input                textinput.Model
	err                  string
	offset               int
}

func sameTestTarget(a, b profile.Profile) bool {
	return a.ID == b.ID && a.Host == b.Host && a.Port == b.Port && a.ProxyJump == b.ProxyJump && a.User == b.User && a.IdentityID == b.IdentityID && slices.Equal(a.Auth, b.Auth) && a.HostKeyFP == b.HostKeyFP && a.HostKey == b.HostKey
}

func observedKey(fp, line string) error {
	if fp == "" || line == "" {
		return fmt.Errorf("server did not supply a complete host key; test again")
	}
	_, err := sshx.HostKeyFingerprint(profile.Profile{HostKeyFP: fp, HostKey: line})
	return err
}
