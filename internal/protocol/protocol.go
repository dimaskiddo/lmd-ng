package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Message type constants for the DBS wire protocol.
// The protocol uses a simple framing format:
//
//	[1-byte msg type][4-byte payload length (big-endian)][payload]
//
// All communication is always encrypted via TLS regardless of transport.
const (
	// MsgScanRequest initiates a file scan session.
	// Payload: EncodeScanRequest(filePath, fileSize)
	MsgScanRequest byte = 0x01

	// MsgScanChunk carries a chunk of file data (max 32KB).
	// Payload: raw file bytes
	MsgScanChunk byte = 0x02

	// MsgScanEnd signals the end of the file data stream.
	// Payload: empty
	MsgScanEnd byte = 0x03

	// MsgScanResult carries the scan result from server to client.
	// Payload: EncodeScanResult(matched, results)
	MsgScanResult byte = 0x04

	// MsgError carries an error message from server to client.
	// Payload: UTF-8 error string
	MsgError byte = 0x05

	// MsgPing is a health-check request from client to server.
	// Payload: empty
	MsgPing byte = 0x06

	// MsgPong is the health-check response from server to client.
	// Payload: empty
	MsgPong byte = 0x07

	// MsgReloadSignatures instructs the server to reload its engines.
	// Payload: empty
	MsgReloadSignatures byte = 0x08

	// MsgReloadAck is the server's acknowledgment of a successful reload.
	// Payload: empty
	MsgReloadAck byte = 0x09
)

const (
	// MaxChunkSize is the maximum size of a single file data chunk.
	MaxChunkSize = 32 * 1024 // 32KB

	// MaxPayloadSize is the absolute maximum payload size for any frame.
	// This protects against malformed frames consuming unbounded memory.
	MaxPayloadSize = 1 * 1024 * 1024 // 1MB

	// frameHeaderSize is the total size of the frame header (type + length).
	frameHeaderSize = 5 // 1 byte type + 4 bytes length
)

// ScanRequestHeader contains metadata about the file being scanned.
type ScanRequestHeader struct {
	FilePath string
	FileSize int64
}

// ScanResultEntry represents a single malware detection.
type ScanResultEntry struct {
	SignatureName string
	SignatureType string
	DetectionID   string
}

// ScanResultMessage is the server's response after scanning a file.
type ScanResultMessage struct {
	Matched bool
	Results []ScanResultEntry
}

// WriteFrame writes a single protocol frame to the writer.
// Frame format: [1-byte msg type][4-byte payload length (big-endian)][payload]
func WriteFrame(w io.Writer, msgType byte, payload []byte) error {
	header := [frameHeaderSize]byte{}
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))

	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("failed to write frame header: %w", err)
	}

	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("failed to write frame payload: %w", err)
		}
	}

	return nil
}

// ReadFrame reads a single protocol frame from the reader.
// Returns the message type, payload bytes, and any error.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	header := [frameHeaderSize]byte{}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, fmt.Errorf("failed to read frame header: %w", err)
	}

	msgType := header[0]
	payloadLen := binary.BigEndian.Uint32(header[1:5])

	if payloadLen > MaxPayloadSize {
		return 0, nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)
	}

	if payloadLen == 0 {
		return msgType, nil, nil
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("failed to read frame payload (%d bytes): %w", payloadLen, err)
	}

	return msgType, payload, nil
}

// EncodeScanRequest serializes a ScanRequestHeader into a wire-format payload.
// Format: [4-byte path length][path bytes][8-byte file size]
func EncodeScanRequest(req *ScanRequestHeader) []byte {
	pathBytes := []byte(req.FilePath)
	buf := make([]byte, 4+len(pathBytes)+8)

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(pathBytes)))
	copy(buf[4:4+len(pathBytes)], pathBytes)
	binary.BigEndian.PutUint64(buf[4+len(pathBytes):], uint64(req.FileSize))

	return buf
}

// DecodeScanRequest deserializes a wire-format payload into a ScanRequestHeader.
func DecodeScanRequest(data []byte) (*ScanRequestHeader, error) {
	if len(data) < 12 { // minimum: 4 (path len) + 0 (empty path) + 8 (file size)
		return nil, fmt.Errorf("scan request payload too short: %d bytes", len(data))
	}

	pathLen := binary.BigEndian.Uint32(data[0:4])
	if uint32(len(data)) < 4+pathLen+8 {
		return nil, fmt.Errorf("scan request payload truncated: need %d, got %d", 4+pathLen+8, len(data))
	}

	filePath := string(data[4 : 4+pathLen])
	fileSize := int64(binary.BigEndian.Uint64(data[4+pathLen : 4+pathLen+8]))

	return &ScanRequestHeader{
		FilePath: filePath,
		FileSize: fileSize,
	}, nil
}

// EncodeScanResult serializes a ScanResultMessage into a wire-format payload.
// Format: [1-byte matched flag][4-byte result count][...entries]
// Each entry: [4-byte name len][name][4-byte type len][type][4-byte id len][id]
func EncodeScanResult(msg *ScanResultMessage) []byte {
	// Calculate total size
	size := 1 + 4 // matched flag + result count
	for _, entry := range msg.Results {
		size += 4 + len(entry.SignatureName) +
			4 + len(entry.SignatureType) +
			4 + len(entry.DetectionID)
	}

	buf := make([]byte, size)
	offset := 0

	// Matched flag
	if msg.Matched {
		buf[offset] = 1
	}
	offset++

	// Result count
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(msg.Results)))
	offset += 4

	// Entries
	for _, entry := range msg.Results {
		offset = writeString(buf, offset, entry.SignatureName)
		offset = writeString(buf, offset, entry.SignatureType)
		offset = writeString(buf, offset, entry.DetectionID)
	}

	return buf
}

// DecodeScanResult deserializes a wire-format payload into a ScanResultMessage.
func DecodeScanResult(data []byte) (*ScanResultMessage, error) {
	if len(data) < 5 { // minimum: 1 (matched) + 4 (count)
		return nil, fmt.Errorf("scan result payload too short: %d bytes", len(data))
	}

	msg := &ScanResultMessage{}
	offset := 0

	msg.Matched = data[offset] == 1
	offset++

	resultCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	msg.Results = make([]ScanResultEntry, 0, resultCount)
	for i := uint32(0); i < resultCount; i++ {
		var entry ScanResultEntry
		var err error

		entry.SignatureName, offset, err = readString(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to read signature name for entry %d: %w", i, err)
		}

		entry.SignatureType, offset, err = readString(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to read signature type for entry %d: %w", i, err)
		}

		entry.DetectionID, offset, err = readString(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to read detection ID for entry %d: %w", i, err)
		}

		msg.Results = append(msg.Results, entry)
	}

	return msg, nil
}

// writeString writes a length-prefixed string into buf at offset, returning the new offset.
func writeString(buf []byte, offset int, s string) int {
	b := []byte(s)
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(b)))
	offset += 4
	copy(buf[offset:offset+len(b)], b)
	return offset + len(b)
}

// readString reads a length-prefixed string from data at offset, returning the string and new offset.
func readString(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", 0, fmt.Errorf("data truncated at offset %d: need 4 bytes for string length", offset)
	}

	strLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+int(strLen) > len(data) {
		return "", 0, fmt.Errorf("data truncated at offset %d: need %d bytes for string", offset, strLen)
	}

	s := string(data[offset : offset+int(strLen)])
	return s, offset + int(strLen), nil
}
