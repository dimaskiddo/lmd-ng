package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// SlackNotifier handles sending notifications to a Slack channel via incoming webhook.
type SlackNotifier struct {
	cfg *config.SlackNotificationConfig
}

// NewSlackNotifier creates a new SlackNotifier with the given configuration.
func NewSlackNotifier(cfg *config.SlackNotificationConfig) *SlackNotifier {
	return &SlackNotifier{
		cfg: cfg,
	}
}

// SendQuarantineNotification sends a Block Kit formatted message to a Slack
// channel indicating a file was quarantined.
func (n *SlackNotifier) SendQuarantineNotification(ctx context.Context, filePath, signatureName string) error {
	if !n.cfg.Enabled || n.cfg.WebhookURL == "" {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Debug("Failed to get hostname, using fallback", "error", err)
		hostname = "Unknown"
	}

	timestamp := time.Now().Format(time.RFC1123)

	payload := map[string]interface{}{
		"text": fmt.Sprintf("LMD-NG Malware Alert — %s detected in %s", signatureName, filePath),
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "🚨 LMD-NG Malware Alert",
				},
			},
			map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("Malware has been detected and successfully quarantined on *%s*.", hostname),
				},
			},
			map[string]interface{}{
				"type": "divider",
			},
			map[string]interface{}{
				"type": "section",
				"fields": []interface{}{
					map[string]interface{}{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Host:*\n%s", hostname),
					},
					map[string]interface{}{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Time:*\n%s", timestamp),
					},
					map[string]interface{}{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*File Path:*\n%s", filePath),
					},
					map[string]interface{}{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Signature:*\n%s", signatureName),
					},
				},
			},
			map[string]interface{}{
				"type": "divider",
			},
			map[string]interface{}{
				"type": "context",
				"elements": []interface{}{
					map[string]interface{}{
						"type": "plain_text",
						"text": "Linux Malware Detect - Next Generation",
					},
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.cfg.WebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status: %d", resp.StatusCode)
	}

	log.Info("Quarantine notification sent to Slack successfully")
	return nil
}

// SendAlert sends a high-priority alert to a Slack channel via incoming webhook.
func (n *SlackNotifier) SendAlert(ctx context.Context, title, message string) error {
	if !n.cfg.Enabled || n.cfg.WebhookURL == "" {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Debug("Failed to get hostname, using fallback", "error", err)
		hostname = "Unknown"
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("[ALERT] %s — %s", title, hostname),
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": fmt.Sprintf("🔴 [ALERT] %s", title),
				},
			},
			map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Host:* %s\n\n%s", hostname, message),
				},
			},
			map[string]interface{}{
				"type": "context",
				"elements": []interface{}{
					map[string]interface{}{
						"type": "plain_text",
						"text": fmt.Sprintf("LMD-NG • %s", time.Now().Format(time.RFC1123)),
					},
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.cfg.WebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status: %d", resp.StatusCode)
	}

	log.Info("Alert notification sent to Slack successfully", "title", title)
	return nil
}
