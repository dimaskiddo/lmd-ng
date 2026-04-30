package notifier

import (
	"strings"
	"fmt"
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
