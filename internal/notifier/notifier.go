package notifier

import (
	"context"
	"errors"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/util"
)

// Notifier defines the interface for sending malware detection and alert
// notifications.
type Notifier interface {
	SendQuarantineNotification(ctx context.Context, filePath, signatureName string) error

	// SendAlert broadcasts a high-priority alert (e.g. integrity/tamper failure).
	SendAlert(ctx context.Context, title, message string) error
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
func (m *MultiNotifier) SendQuarantineNotification(ctx context.Context, filePath, signatureName string) error {
	if len(m.notifiers) == 0 {
		return nil
	}

	if !util.HasInternetAccess() {
		log.Debug("No internet connection detected, dropping notification", "file", filePath)
		return nil
	}

	var errs []error

	for _, n := range m.notifiers {
		if err := n.SendQuarantineNotification(ctx, filePath, signatureName); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// SendAlert broadcasts a high-priority alert to all configured notifiers.
func (m *MultiNotifier) SendAlert(ctx context.Context, title, message string) error {
	if len(m.notifiers) == 0 {
		return nil
	}

	if !util.HasInternetAccess() {
		log.Debug("No internet connection detected, dropping alert notification", "title", title)
		return nil
	}

	var errs []error

	for _, n := range m.notifiers {
		if err := n.SendAlert(ctx, title, message); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
