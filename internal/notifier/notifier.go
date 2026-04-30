package notifier

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// Notifier defines the interface for sending malware detection notifications.
type Notifier interface {
	SendQuarantineNotification(filePath, signatureName string) error
}

// MultiNotifier holds multiple Notifier implementations and broadcasts to all of them.
type MultiNotifier struct {
	notifiers []Notifier
}

// NewMultiNotifier creates a new MultiNotifier.
func NewMultiNotifier(notifiers ...Notifier) *MultiNotifier {
	return &MultiNotifier{
		notifiers: notifiers,
	}
}

// SendQuarantineNotification broadcasts the notification to all configured notifiers.
// It aggregates any errors encountered into a single error.
func (m *MultiNotifier) SendQuarantineNotification(filePath, signatureName string) error {
	if len(m.notifiers) == 0 {
		return nil
	}

	// Fast internet connectivity check. If there is no internet, we silently
	// drop the notification to avoid hanging goroutines waiting for timeouts.
	if !hasInternetAccess() {
		log.Debug("No internet connection detected, dropping notification", "file", filePath)
		return nil
	}

	var errs []string

	for _, n := range m.notifiers {
		if err := n.SendQuarantineNotification(filePath, signatureName); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple notification errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// hasInternetAccess performs a fast TCP dial to a highly available public domain
// to determine if the system has working DNS resolution and outbound internet access.
func hasInternetAccess() bool {
	conn, err := net.DialTimeout("tcp", "google.com:443", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()

	return true
}
