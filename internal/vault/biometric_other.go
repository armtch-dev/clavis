//go:build !darwin || !cgo

package vault

// authenticateLocal is a no-op where LocalAuthentication isn't available
// (non-darwin, or a cgo-less cross build) — the keychain read itself is
// darwin-only, so this only preserves today's ungated behavior there.
func authenticateLocal(string) error { return nil }
