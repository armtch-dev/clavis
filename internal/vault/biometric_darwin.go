//go:build darwin && cgo

package vault

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#import <LocalAuthentication/LocalAuthentication.h>

// clavis_authenticate blocks on the system auth sheet (Touch ID, Apple
// Watch, or account password) and returns 1 on success, 0 on decline,
// -1 when no auth method can be evaluated (headless session, SSH, …).
static int clavis_authenticate(const char *reason) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *err = nil;
	if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&err]) {
		return -1;
	}
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	__block int ok = 0;
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
		localizedReason:[NSString stringWithUTF8String:reason]
		reply:^(BOOL success, NSError *error) {
			ok = success ? 1 : 0;
			dispatch_semaphore_signal(sem);
		}];
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	return ok;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// authenticateLocal gates the cached master key behind device-owner auth.
// ponytail: UI-level gate, not cryptographic binding — the key still lives in
// the login keychain; upgrade path is a Secure-Enclave-wrapped key, which
// needs a signed + entitled binary.
func authenticateLocal(reason string) error {
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	switch C.clavis_authenticate(cr) {
	case 1:
		return nil
	case -1:
		return errors.New("local authentication unavailable in this session")
	default:
		return errors.New("authentication declined")
	}
}
