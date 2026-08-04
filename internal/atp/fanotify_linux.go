//go:build linux

package atp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"golang.org/x/sys/unix"
)

// fanotifyEventMetadata mirrors struct fanotify_event_metadata (kernel ABI).
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

// inodeSet maps device -> set of inodes for O(1) protected-file probes.
type inodeSet map[uint64]map[uint64]struct{}

func (s inodeSet) has(dev, ino uint64) bool {
	inodes, ok := s[dev]
	if !ok {
		return false
	}
	_, exists := inodes[ino]
	return exists
}

// markAll marks every protected path on the fanotify fd.
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

// flushMarks removes all marks from the fanotify fd.
func flushMarks(fd int) {
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, ""); err != nil {
		log.Debug("ATP: fanotify mark flush failed", "error", err)
	}
}

// waitUntilShutdown blocks until ctx is cancelled or a shutdown command is
// received. Used when fanotify is unavailable so the goroutine still terminates
// cleanly with the daemon.
func waitUntilShutdown(ctx context.Context, control <-chan string) {
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

// startMonitor runs the fanotify permission-event loop until ctx is cancelled
// or a shutdown/unlock command is received.
func (p *Protector) startMonitor(ctx context.Context, files []string, control <-chan string) {
	go p.startInotifyMonitor(ctx, files)

	fd, err := unix.FanotifyInit(unix.FAN_CLASS_PRE_CONTENT, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		log.Warn("ATP: fanotify_init failed",
			"error", err)
		waitUntilShutdown(ctx, control)
		return
	}
	defer unix.Close(fd)

	marked := markAll(fd, files)
	log.Info("ATP: fanotify permission listener active", "watched_files", marked)

	protected := p.buildInodeSet(files)

	buf := make([]byte, 65536)
	var consecutiveErrors int

	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-control:
			switch cmd {
			case "shutdown":
				return
			case "unlock":
				flushMarks(fd)
			case "lock":
				markAll(fd, files)
			}
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
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

			if errors.Is(err, syscall.EBADF) {
				// The fanotify fd is stale after sleep/hibernate. Closing it
				// destroys the group and auto-allows pending permission events,
				// unblocking processes waiting on a FAN_OPEN_PERM response.
				log.Warn("ATP: fanotify fd stale (post-sleep/hibernate), re-initializing")
				unix.Close(fd)

				fd, err = unix.FanotifyInit(unix.FAN_CLASS_PRE_CONTENT, unix.O_CLOEXEC|unix.O_NONBLOCK)
				if err != nil {
					log.Warn("ATP: fanotify re-init failed — protection limited to immutable flags",
						"error", err)
					waitUntilShutdown(ctx, control)
					return
				}
				marked := markAll(fd, files)
				log.Info("ATP: fanotify permission listener re-initialized", "watched_files", marked)
				consecutiveErrors = 0
				continue
			}

			// EINTR and transient errors are retried, debounced to avoid a
			// tight spin if an unexpected error persists.
			consecutiveErrors++
			if consecutiveErrors >= 10 {
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case cmd := <-control:
					timer.Stop()
					if cmd == "shutdown" {
						return
					}
				case <-timer.C:
				}
				consecutiveErrors = 0
			}
			log.Debug("ATP: fanotify read", "error", err)
			continue
		}

		consecutiveErrors = 0
		p.handleEvents(buf[:n], fd, protected)
	}
}

// handleEvents processes raw fanotify events and responds to FAN_OPEN_PERM.
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

	if int(meta.Pid) == os.Getpid() {
		writeResponse(fd, resp)
		return
	}

	target, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
	if err != nil {
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

// writeResponse writes a fanotify response to the fanotify fd.
func writeResponse(fd int, resp fanotifyResponse) {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:4], uint32(resp.Fd))
	binary.LittleEndian.PutUint32(b[4:8], resp.Response)
	if _, err := unix.Write(fd, b[:]); err != nil {
		log.Debug("ATP: fanotify response write", "error", err)
	}
}

// buildInodeSet snapshots the device/inode pairs of all protected files.
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
