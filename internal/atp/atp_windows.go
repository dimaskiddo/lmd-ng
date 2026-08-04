//go:build windows

package atp

import (
	"context"
	"fmt"
	"os"
	"unsafe"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"golang.org/x/sys/windows"
)

// exclusiveHandles holds the file handles held open with dwShareMode=0,
// preventing rename/delete of protected files for as long as they are open.
var exclusiveHandles []windows.Handle

// applyProtection applies the deny-write DACL, audit SACL, and exclusive
// handles to every protected file. ATP is mandatory — no config toggles.
func (p *Protector) applyProtection(files []string) error {
	var errs []error

	// Phase 1: Deny-write DACL (everyone denied FILE_WRITE_DATA, DELETE, ...).
	for _, f := range files {
		if err := setDenyWriteDACL(f); err != nil {
			log.Warn("ATP: failed to set deny-write DACL", "file", f, "error", err)
			errs = append(errs, err)
		}
	}

	// Phase 2: Audit SACL for failed write/delete attempts (best-effort).
	for _, f := range files {
		if err := setAuditSACL(f); err != nil {
			log.Warn("ATP: failed to set audit SACL", "file", f, "error", err)
		}
	}

	// Phase 3: Exclusive handles — the strongest layer, holds each file open
	// with dwShareMode=0 so even SYSTEM cannot rename/delete it.
	for _, f := range files {
		handle, err := holdExclusiveHandle(f)
		if err != nil {
			log.Debug("ATP: exclusive handle not acquired", "file", f, "error", err)
			continue
		}
		exclusiveHandles = append(exclusiveHandles, handle)
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to protect %d files: %w", len(errs), errs[0])
	}
	return nil
}

// removeProtection releases all exclusive handles (the DACL/SACL are
// persistent and do not need explicit release).
func (p *Protector) removeProtection(files []string) error {
	seen := make(map[windows.Handle]struct{}, len(exclusiveHandles))
	for _, h := range exclusiveHandles {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		windows.CloseHandle(h)
	}
	exclusiveHandles = nil
	log.Info("ATP: released all exclusive file handles")
	return nil
}

// setDenyWriteDACL adds a DENY_ACCESS ACE blocking FILE_WRITE_DATA,
// FILE_APPEND_DATA, DELETE, WRITE_DAC, and WRITE_OWNER for Everyone.
//
// ponytail: SYSTEM can take ownership and rewrite the DACL via
// SeTakeOwnershipPrivilege, so this is a speed bump — the exclusive handle
// is the real barrier.
func setDenyWriteDACL(path string) error {
	everyone, err := windows.StringToSid("S-1-1-0") // Everyone
	if err != nil {
		return fmt.Errorf("StringToSid(Everyone): %w", err)
	}

	accessMask := windows.ACCESS_MASK(windows.DELETE) | windows.ACCESS_MASK(windows.FILE_WRITE_DATA) |
		windows.ACCESS_MASK(windows.FILE_APPEND_DATA) | windows.ACCESS_MASK(windows.WRITE_DAC) | windows.ACCESS_MASK(windows.WRITE_OWNER)

	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: accessMask,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValue(unsafe.Pointer(everyone)),
		},
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, nil)
	if err != nil {
		return fmt.Errorf("ACLFromEntries: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo(DACL): %w", err)
	}

	log.Debug("ATP: deny-write DACL set", "file", path)
	return nil
}

// setAuditSACL adds SYSTEM_AUDIT_ACE entries that log failed write/delete
// attempts to the Security event log. Requires SeSecurityPrivilege.
func setAuditSACL(path string) error {
	// SeSecurityPrivilege is disabled by default even on SYSTEM; enable it.
	if err := enablePrivilege("SeSecurityPrivilege"); err != nil {
		log.Debug("ATP: SeSecurityPrivilege unavailable (SACL audit skipped)",
			"error", err)
		return nil // best-effort
	}

	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		return nil
	}

	accessMask := windows.ACCESS_MASK(windows.DELETE) | windows.ACCESS_MASK(windows.FILE_WRITE_DATA) | windows.ACCESS_MASK(windows.WRITE_DAC)

	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: accessMask,
		AccessMode:        windows.SET_AUDIT_FAILURE,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValue(unsafe.Pointer(everyone)),
		},
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, nil)
	if err != nil {
		return fmt.Errorf("ACLFromEntries(SACL): %w", err)
	}

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.SACL_SECURITY_INFORMATION, nil, nil, nil, acl); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo(SACL): %w", err)
	}

	log.Debug("ATP: audit SACL set", "file", path)
	return nil
}

// holdExclusiveHandle opens the file with dwShareMode=0, so no other process
// can open it for read, write, or delete while the handle is open.
func holdExclusiveHandle(path string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		0, // dwShareMode=0 -> exclusive
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateFile(exclusive): %w", err)
	}

	log.Debug("ATP: exclusive handle held", "file", path)
	return handle, nil
}

// enablePrivilege enables a named privilege in the current process token.
func enablePrivilege(name string) error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// recheckFiles verifies protected files still exist. DACLs are persistent on
// Windows; the primary failure mode is deletion, which is blocked by the
// exclusive handle but not if the handle was lost.
func (p *Protector) recheckFiles(files []string) {
	log.Debug("ATP: Windows periodic recheck — verifying file existence", "count", len(files))
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			log.Warn("ATP: protected file deleted", "file", f)
		}
	}
}

// isImmutableSet reports whether a protected file exists (the Windows
// equivalent of the immutable-flag probe on Unix).
func isImmutableSet(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// startMonitor is a no-op on Windows — the DACL and exclusive handles are
// enforced by the kernel at open time. SACL events go to the Security event
// log, which RTP can monitor separately.
func (p *Protector) startMonitor(ctx context.Context, files []string, control <-chan string) {
	log.Debug("ATP: Windows — no permission listener needed (DACL + exclusive handle cover it)")
	<-ctx.Done()
}
