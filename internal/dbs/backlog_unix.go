//go:build !windows

package dbs

import "syscall"

// setBacklog sets the listen backlog on a file descriptor.
// On Unix-like systems, the file descriptor is an int.
func setBacklog(fd uintptr, backlog int) error {
	return syscall.Listen(int(fd), backlog)
}
