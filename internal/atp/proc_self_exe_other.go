//go:build !linux

package atp

// SelfExeDeleted always returns false off Linux — the " (deleted)" inode
// indicator in /proc/self/exe is Linux-specific.
func SelfExeDeleted() bool {
	return false
}

func selfExeDeleted() bool { return SelfExeDeleted() }
