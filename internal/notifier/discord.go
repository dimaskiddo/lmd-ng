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

// DiscordEmbed represents a Discord message embed.
type DiscordEmbed struct {
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color,omitempty"`
	Fields      []DiscordField `json:"fields,omitempty"`
	Footer      *DiscordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

// DiscordField represents a field within a Discord embed.
type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// DiscordFooter represents the footer of a Discord embed.
type DiscordFooter struct {
	Text string `json:"text"`
}

// DiscordPayload is the top-level JSON payload sent to a Discord webhook.
type DiscordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []DiscordEmbed `json:"embeds,omitempty"`
}

// DiscordNotifier handles sending notifications to a Discord channel via webhook.
type DiscordNotifier struct {
	cfg *config.DiscordNotificationConfig
}

// NewDiscordNotifier creates a new DiscordNotifier with the given configuration.
func NewDiscordNotifier(cfg *config.DiscordNotificationConfig) *DiscordNotifier {
	return &DiscordNotifier{
		cfg: cfg,
	}
}

// SendQuarantineNotification sends a rich embed message to a Discord channel
// indicating a file was quarantined.
func (n *DiscordNotifier) SendQuarantineNotification(ctx context.Context, filePath, signatureName string) error {
	if !n.cfg.Enabled || n.cfg.WebhookURL == "" {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Debug("Failed to get hostname, using fallback", "error", err)
		hostname = "Unknown"
	}

	timestamp := time.Now().Format(time.RFC1123)

	payload := DiscordPayload{
		Username: "LMD-NG",
		Embeds: []DiscordEmbed{
			{
				Title:       "LMD-NG Malware Alert",
				Description: fmt.Sprintf("Malware has been detected and successfully quarantined on **%s**.", hostname),
				Color:       15158332, // Red
				Fields: []DiscordField{
					{Name: "Host", Value: hostname},
					{Name: "Time", Value: timestamp},
					{Name: "File Path", Value: "`" + filePath + "`"},
					{Name: "Signature", Value: signatureName},
				},
				Footer:    &DiscordFooter{Text: "Linux Malware Detect - Next Generation"},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.cfg.WebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send discord request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discord webhook returned status: %d", resp.StatusCode)
	}

	log.Info("Quarantine notification sent to Discord successfully")
	return nil
}

// SendAlert sends a high-priority alert embed to a Discord channel.
func (n *DiscordNotifier) SendAlert(ctx context.Context, title, message string) error {
	if !n.cfg.Enabled || n.cfg.WebhookURL == "" {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Debug("Failed to get hostname, using fallback", "error", err)
		hostname = "Unknown"
	}

	payload := DiscordPayload{
		Username: "LMD-NG Alert",
		Embeds: []DiscordEmbed{
			{
				Title:       fmt.Sprintf("🔴 [ALERT] %s", title),
				Description: fmt.Sprintf("**Host:** %s\n\n%s", hostname, message),
				Color:       0xFF0000,
				Footer:      &DiscordFooter{Text: "Linux Malware Detect - Next Generation"},
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.cfg.WebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send discord request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discord webhook returned status: %d", resp.StatusCode)
	}

	log.Info("Alert notification sent to Discord successfully", "title", title)
	return nil
}
