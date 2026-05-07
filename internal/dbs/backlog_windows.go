//go:build windows

package dbs

import "syscall"

// setBacklog sets the listen backlog on a file descriptor.
// On Windows, the file descriptor is a syscall.Handle.
func setBacklog(fd uintptr, backlog int) error {
	return syscall.Listen(syscall.Handle(fd), backlog)
}
