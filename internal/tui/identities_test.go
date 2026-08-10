package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/profile"
)

// The headline behaviour: one identity authenticates many profiles — the
// bound profile resolves the identity's user and vault secrets live.
func TestIdentityBackedProfileResolvesCreds(t *testing.T) {
	m := newTestModel(t)

	id, err := m.idents.Add(profile.Identity{
		Name: "ops", User: "opsuser", Auth: []profile.AuthKind{profile.AuthPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(id.PassSecret(), []byte("sekrit")); err != nil {
		t.Fatal(err)
	}
	p, err := m.store.Add(profile.Profile{
		Name: "web", Host: "192.0.2.9", Port: 22, IdentityID: id.ID,
	})
	if err != nil {
		t.Fatalf("identity-backed profile should validate without user/auth: %v", err)
	}

	ep := m.effective(*p)
	if ep.User != "opsuser" {
		t.Fatalf("effective user = %q, want the identity's", ep.User)
	}
	if !ep.HasAuth(profile.AuthPassword) {
		t.Fatal("effective auth should come from the identity")
	}
	creds, err := m.credsFor(&ep)
	if err != nil {
		t.Fatalf("credsFor: %v", err)
	}
	if creds.Password != "sekrit" {
		t.Fatalf("password = %q, want the identity's secret", creds.Password)
	}

	// Editing the identity updates every bound profile — no denormalized copy.
	id2 := *m.idents.ByID(id.ID)
	id2.User = "renamed"
	if err := m.idents.Update(id2); err != nil {
		t.Fatal(err)
	}
	if got := m.effective(*p).User; got != "renamed" {
		t.Fatalf("after identity edit, effective user = %q, want renamed", got)
	}
}

// The identity wizard shares the profile wizard's machinery: identity mode
// must drop every host-specific step, including the connection test.
func TestIdentityWizardSequence(t *testing.T) {
	m := newTestModel(t)
	w := newIdentityWizard(m, nil)
	for _, s := range w.sequence() {
		switch s {
		case stepHost, stepPort, stepIdentity, stepProxyJump, stepCategory, stepTags, stepTest:
			t.Fatalf("identity wizard sequence must not contain step %v", s)
		}
	}
}

// Deleting an identity that profiles depend on is refused in the manager.
func TestIdentityDeleteBlockedWhileInUse(t *testing.T) {
	m := newTestModel(t)
	id, _ := m.idents.Add(profile.Identity{
		Name: "ops", User: "ops", Auth: []profile.AuthKind{profile.AuthPassword},
	})
	m.store.Add(profile.Profile{Name: "web", Host: "192.0.2.9", IdentityID: id.ID})

	m.identsUI = &identsModel{}
	m.screen = scrIdentities
	m.updateIdentities(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if m.identsUI.confirmDel {
		t.Fatal("delete must not reach confirmation while the identity is in use")
	}
	if m.idents.ByID(id.ID) == nil {
		t.Fatal("identity must survive")
	}
}
