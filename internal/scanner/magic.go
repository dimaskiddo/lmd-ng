package scanner

import "bytes"

// magicType constants mirror the ClamAV NDB TargetType values, used internally
// by the scanner package to classify files by their magic bytes without creating
// a dependency on pkg/clamav.
const (
	magicTypeAny   = 0 // Unknown / generic — apply all signatures
	magicTypePE    = 1 // Windows PE / DOS executable (MZ header)
	magicTypeELF   = 6 // ELF executable or shared library (Linux/Unix)
	magicTypeMachO = 9 // Mach-O executable or library (macOS/iOS)
)

// Well-known file-type magic byte sequences.
var (
	sigMagicELF      = []byte{0x7F, 0x45, 0x4C, 0x46} // \x7fELF
	sigMagicMZ       = []byte{0x4D, 0x5A}             // MZ (DOS/PE)
	sigMagicMachO32  = []byte{0xCE, 0xFA, 0xED, 0xFE} // Mach-O 32-bit LE
	sigMagicMachO64  = []byte{0xCF, 0xFA, 0xED, 0xFE} // Mach-O 64-bit LE
	sigMagicMachO32B = []byte{0xFE, 0xED, 0xFA, 0xCE} // Mach-O 32-bit BE
	sigMagicMachO64B = []byte{0xFE, 0xED, 0xFA, 0xCF} // Mach-O 64-bit BE
)

// detectMagicType inspects the leading bytes of content and returns the
// magicType constant that best describes the file format. It returns
// magicTypeAny when the format is unrecognised.
//
// ELF is checked before PE because some toolchains prepend an MZ stub to
// ELF binaries (e.g. UEFI applications), which would otherwise be misclassified.
func detectMagicType(content []byte) int {
	if len(content) < 2 {
		return magicTypeAny
	}

	// ELF shared library / executable: \x7fELF
	if len(content) >= 4 && bytes.HasPrefix(content, sigMagicELF) {
		return magicTypeELF
	}

	// Windows PE / DOS executable: MZ
	if bytes.HasPrefix(content, sigMagicMZ) {
		return magicTypePE
	}

	// Mach-O (all endianness and bitness variants)
	if len(content) >= 4 {
		prefix4 := content[:4]
		if bytes.Equal(prefix4, sigMagicMachO32) || bytes.Equal(prefix4, sigMagicMachO64) ||
			bytes.Equal(prefix4, sigMagicMachO32B) || bytes.Equal(prefix4, sigMagicMachO64B) {
			return magicTypeMachO
		}
	}

	return magicTypeAny
}

// isNativeExecutable returns true if the detected magic type is a native
// executable or shared library (ELF or Mach-O). Used by the HEX engine to
// avoid applying Windows-specific patterns to non-Windows binaries.
func isNativeExecutable(magicType int) bool {
	return magicType == magicTypeELF || magicType == magicTypeMachO
}

// winTargetedPrefixes are the signature name prefixes that unambiguously
// indicate a Windows-targeted threat. HEX signatures whose names start with
// any of these prefixes are skipped when scanning ELF / Mach-O files.
var winTargetedPrefixes = []string{
	"Win.",
	"Worm.",
	"Backdoor.Win",
	"Trojan.Win",
	"Adware.Win",
	"Spyware.Win",
	"Ransom.Win",
	"Exploit.Win",
	"Downloader.Win",
	"Dropper.Win",
}

// isWindowsTargetedSig returns true if the signature name begins with any of
// the well-known Windows-targeted threat family prefixes.
func isWindowsTargetedSig(name string) bool {
	for _, prefix := range winTargetedPrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}
