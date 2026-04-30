package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// TelegramNotifier handles sending notifications to a Telegram chat.
type TelegramNotifier struct {
	cfg *config.TelegramNotificationConfig
}

// NewTelegramNotifier creates a new TelegramNotifier with the given configuration.
func NewTelegramNotifier(cfg *config.TelegramNotificationConfig) *TelegramNotifier {
	return &TelegramNotifier{
		cfg: cfg,
	}
}

// SendQuarantineNotification sends an HTML formatted message to Telegram indicating a file was quarantined.
func (n *TelegramNotifier) SendQuarantineNotification(filePath, signatureName string) error {
	if !n.cfg.Enabled || n.cfg.BotToken == "" || n.cfg.ChatID == "" {
		return nil
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "Unknown"
	}

	timestamp := time.Now().Format(time.RFC1123)

	message := fmt.Sprintf(
		"🚨 <b>LMD-NG Malware Alert</b>\n\n"+
			"Malware has been detected and successfully quarantined.\n\n"+
			"<b>Host:</b> %s\n"+
			"<b>Time:</b> %s\n"+
			"<b>File Path:</b> <code>%s</code>\n"+
			"<b>Signature:</b> %s",
		hostname, timestamp, filePath, signatureName,
	)

	payload := map[string]interface{}{
		"chat_id":    n.cfg.ChatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.BotToken)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status: %d", resp.StatusCode)
	}

	log.Info("Quarantine notification sent to Telegram successfully")
	return nil
}
