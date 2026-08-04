//go:build linux

package atp

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"golang.org/x/sys/unix"
)

// fanotifyEventMetadata mirrors the kernel struct fanotify_event_metadata.
// Layout must match the ABI exactly — see linux/fanotify.h.
type fanotifyEventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

// fanotifyResponse is written back to the fanotify fd to permit or deny a
// pending permission event.
type fanotifyResponse struct {
	Fd       int32
	Response uint32
}

// fanotify permission responses.
const (
	respAllow uint32 = 0 // FAN_ALLOW
	respDeny  uint32 = 1 // FAN_DENY
)

// inodeSet maps device -> set of inodes. Provides an O(1) probe for "is this
// inode one of the protected files?"
type inodeSet map[uint64]map[uint64]struct{}

func (s inodeSet) has(dev, ino uint64) bool {
	inodes, ok := s[dev]
	if !ok {
		return false
	}
	_, exists := inodes[ino]
	return exists
}

// markAll marks every protected path on the fanotify fd. FAN_OPEN_PERM
// permission events are requested so we can deny unauthorized write opens.
func markAll(fd int, files []string) int {
	marked := 0
	for _, f := range files {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, f); err != nil {
			log.Debug("ATP: fanotify mark failed", "path", f, "error", err)
			continue
		}
		marked++
	}
	return marked
}

// flushMarks removes all marks from the fanotify fd, so pending permission
// events auto-allow. Used during the upgrade unlock window.
func flushMarks(fd int) {
	// FAN_MARK_FLUSH removes all marks for the group.
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, ""); err != nil {
		log.Debug("ATP: fanotify mark flush failed", "error", err)
	}
}

// startMonitor runs the fanotify permission-event loop until ctx is
// cancelled or "shutdown"/"unlock" is received on control. It also launches
// the inotify detection layer as an independent goroutine.
//
// CGO note: fanotify_init/fanotify_mark in the vendored golang.org/x/sys/unix
// are pure Go syscalls (Syscall/Syscall6) — no libc, no CGO. Verified against
// vendor/golang.org/x/sys/unix/zsyscall_linux.go.
func (p *Protector) startMonitor(ctx context.Context, files []string, control <-chan string) {
	// Independent detection layer: inotify observes attribute changes (chattr -i)
	// and direct modifications, re-applying the immutable flag when cleared.
	go p.startInotifyMonitor(ctx, files)

	// fanotify_init in permission mode. Events are read on fd; responses are
	// written on fd. FAN_CLASS_PRE_CONTENT is the highest privilege class and
	// the only one capable of denying based on content-class operations.
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_PRE_CONTENT, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		// Kernel too old or lacking CAP_SYS_ADMIN — fall back to chattr only.
		log.Warn("ATP: fanotify_init failed — continuing with immutable flags only",
			"error", err)
		// Consume control channel until shutdown so the periodic recheck
		// remains the only active protection.
		for {
			select {
			case <-ctx.Done():
				return
			case cmd := <-control:
				if cmd == "shutdown" {
					return
				}
			}
		}
	}
	defer unix.Close(fd)

	marked := markAll(fd, files)
	log.Info("ATP: fanotify permission listener active", "watched_files", marked)

	protected := p.buildInodeSet(files)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-control:
			switch cmd {
			case "shutdown":
				return
			case "unlock":
				// Release marks so LMD-NG's own upgrade can write freely.
				flushMarks(fd)
			case "lock":
				markAll(fd, files)
			}
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// No pending events — brief sleep to avoid a hot loop on the
				// non-blocking fd. A 50ms backoff keeps latency negligible.
				timer := time.NewTimer(50 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case cmd := <-control:
					timer.Stop()
					switch cmd {
					case "shutdown":
						return
					case "unlock":
						flushMarks(fd)
					case "lock":
						markAll(fd, files)
					}
				case <-timer.C:
				}
				continue
			}
			// EINTR and transient errors are retried.
			log.Debug("ATP: fanotify read", "error", err)
			continue
		}

		p.handleEvents(buf[:n], fd, protected)
	}
}

// handleEvents processes raw fanotify events from the read buffer and writes
// responses for each FAN_OPEN_PERM event.
func (p *Protector) handleEvents(buf []byte, fd int, protected inodeSet) {
	offset := 0
	for offset+int(unsafe.Sizeof(fanotifyEventMetadata{})) <= len(buf) {
		meta := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
		if meta.EventLen < uint32(unsafe.Sizeof(fanotifyEventMetadata{})) {
			break
		}
		if meta.EventLen == 0 {
			break
		}

		if meta.Mask&unix.FAN_OPEN_PERM != 0 {
			p.respond(fd, meta, protected)
		}

		if meta.Fd >= 0 {
			unix.Close(int(meta.Fd))
		}

		offset += int(meta.EventLen)
	}
}

// respond decides allow/deny for a single open-permission event and writes
// the response back to the fanotify fd.
func (p *Protector) respond(fd int, meta *fanotifyEventMetadata, protected inodeSet) {
	resp := fanotifyResponse{Fd: meta.Fd, Response: respAllow}

	// Our own process and its upgrade subprocesses are always allowed.
	if int(meta.Pid) == os.Getpid() {
		writeResponse(fd, resp)
		return
	}

	// Resolve the target inode of the file being opened.
	target, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
	if err != nil {
		// Cannot verify — fail open to avoid breaking unrelated access.
		writeResponse(fd, resp)
		return
	}

	st, ok := target.Sys().(*syscall.Stat_t)
	if !ok {
		writeResponse(fd, resp)
		return
	}

	if protected.has(uint64(st.Dev), st.Ino) {
		resp.Response = respDeny
		log.Warn("ATP: denied write open on protected file",
			"pid", meta.Pid, "inode", st.Ino)
	}

	writeResponse(fd, resp)
}

// writeResponse writes a fanotify_response to the fanotify fd.
func writeResponse(fd int, resp fanotifyResponse) {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:4], uint32(resp.Fd))
	binary.LittleEndian.PutUint32(b[4:8], resp.Response)
	if _, err := unix.Write(fd, b[:]); err != nil {
		log.Debug("ATP: fanotify response write", "error", err)
	}
}

// buildInodeSet snapshots the device/inode pairs of all protected files for
// fast lookup inside the event loop.
func (p *Protector) buildInodeSet(files []string) inodeSet {
	set := make(inodeSet)
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if _, ok := set[uint64(st.Dev)]; !ok {
			set[uint64(st.Dev)] = make(map[uint64]struct{})
		}
		set[uint64(st.Dev)][st.Ino] = struct{}{}
	}
	return set
}
