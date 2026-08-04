//go:build windows

package atp

import (
	"context"
	"errors"
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
// handles to every protected file.
func (p *Protector) applyProtection(files []string) error {
	var errs []error

	for _, f := range files {
		if err := setDenyWriteDACL(f); err != nil {
			log.Warn("ATP: failed to set deny-write DACL", "file", f, "error", err)
			errs = append(errs, err)
		}
	}

	for _, f := range files {
		if err := setAuditSACL(f); err != nil {
			log.Warn("ATP: failed to set audit SACL", "file", f, "error", err)
		}
	}

	for _, f := range files {
		handle, err := holdExclusiveHandle(f)
		if err != nil {
			log.Debug("ATP: exclusive handle not acquired", "file", f, "error", err)
			continue
		}
		exclusiveHandles = append(exclusiveHandles, handle)
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to protect %d files: %w", len(errs), errors.Join(errs...))
	}
	return nil
}

// removeProtection releases all exclusive handles.
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

// setDenyWriteDACL adds a DENY_ACCESS ACE blocking write/delete for Everyone.
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

// setAuditSACL adds SYSTEM_AUDIT_ACE entries that log failed write/delete attempts.
func setAuditSACL(path string) error {
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

// holdExclusiveHandle opens the file with dwShareMode=0, blocking other opens.
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

// recheckFiles verifies protected files still exist.
func (p *Protector) recheckFiles(files []string) {
	log.Debug("ATP: Windows periodic recheck — verifying file existence", "count", len(files))
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			log.Warn("ATP: protected file deleted", "file", f)
		}
	}
}

// IsImmuneSet reports whether a protected file is protected (exists; Windows
// holds exclusive handles in-process, so cross-process there is no persistent
// flag to probe).
func IsImmuneSet(path string) bool { return isImmutableSet(path) }

// isImmutableSet reports whether a protected file exists.
func isImmutableSet(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// startMonitor is a no-op on Windows.
func (p *Protector) startMonitor(ctx context.Context, files []string, control <-chan string) {
	log.Debug("ATP: Windows — no permission listener needed")
	<-ctx.Done()
}
