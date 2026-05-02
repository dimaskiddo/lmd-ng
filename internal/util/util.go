package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func ParseSizeString(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	if len(sizeStr) == 0 {
		return 0, fmt.Errorf("empty size string")
	}

	lastChar := sizeStr[len(sizeStr)-1]
	suffix := strings.ToLower(string(lastChar))

	valueStr := sizeStr
	var multiplier int64 = 1

	switch suffix {
	case "k":
		multiplier = 1024
		valueStr = sizeStr[:len(sizeStr)-1]
	case "m":
		multiplier = 1024 * 1024
		valueStr = sizeStr[:len(sizeStr)-1]
	case "g":
		multiplier = 1024 * 1024 * 1024
		valueStr = sizeStr[:len(sizeStr)-1]
	default:
		// No suffix, or Unknown suffix
		// Assume Bytes
		if !('0' <= lastChar && lastChar <= '9') {
			return 0, fmt.Errorf("invalid size suffix: %s", sizeStr)
		}
	}

	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value in size string %s: %w", sizeStr, err)
	}

	return value * multiplier, nil
}

// HasInternetAccess performs a fast TCP dial to a highly available public domain
// to determine if the system has working DNS resolution and outbound internet access.
func HasInternetAccess() bool {
	conn, err := net.DialTimeout("tcp", "google.com:443", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()

	return true
}
