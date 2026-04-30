package clamav

import (
	"testing"
)

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected int
	}{
		{"ELF binary", append([]byte{0x7F, 0x45, 0x4C, 0x46}, make([]byte, 60)...), NDBTargetELF},
		{"PE/Windows exe", append([]byte{0x4D, 0x5A}, make([]byte, 60)...), NDBTargetPE},
		{"OLE2 document", append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, 60)...), NDBTargetOLE2},
		{"Mach-O 64-bit LE", []byte{0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01}, NDBTargetMachO},
		{"Mach-O 32-bit LE", []byte{0xCE, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x00}, NDBTargetMachO},
		{"Unknown / generic", []byte{0x89, 0x50, 0x4E, 0x47}, NDBTargetAny},
		{"Empty content", []byte{}, NDBTargetAny},
		{"Short content", []byte{0x4D}, NDBTargetAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFileType(tt.content)
			if got != tt.expected {
				t.Errorf("detectFileType() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestNDBMatchTargetTypeFiltering(t *testing.T) {
	store := NewNDBStore()

	// Add a Win.Trojan sig (TargetType=1/PE) with a simple pattern that is
	// present in both our "PE" and "ELF" test buffers below.
	pattern := "deadbeef"
	sig, err := compileNDBSignature("Win.Trojan.TestOnly", NDBTargetPE, "*", pattern)
	if err != nil {
		t.Fatalf("compileNDBSignature failed: %v", err)
	}
	store.Signatures = append(store.Signatures, sig)

	// ELF content containing the pattern — should NOT match a PE-only sig.
	elfContent := append([]byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00}, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)
	matches := store.Match(elfContent, int64(len(elfContent)))
	if len(matches) != 0 {
		t.Errorf("PE sig should NOT match ELF binary, but got: %v", matches)
	}

	// PE content containing the pattern — SHOULD match.
	peContent := append([]byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)
	matches = store.Match(peContent, int64(len(peContent)))
	if len(matches) != 1 || matches[0] != "Win.Trojan.TestOnly" {
		t.Errorf("PE sig should match PE binary, got: %v", matches)
	}

	// Unknown-type content containing the pattern — should NOT match.
	// We now strictly skip PE (1) signatures on unknown files because PE is robustly detectable.
	unknownContent := append([]byte{0x89, 0x50, 0x4E, 0x47}, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)
	matches = store.Match(unknownContent, int64(len(unknownContent)))
	if len(matches) != 0 {
		t.Errorf("PE sig should NOT match unknown-type content, goit: %v", matches)
	}
}
