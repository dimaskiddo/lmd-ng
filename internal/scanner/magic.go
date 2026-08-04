package scanner

import "bytes"

// magicType constants classify files by their magic bytes. Values mirror the
// ClamAV NDB TargetType values.
const (
	magicTypeAny   = 0
	magicTypePE    = 1
	magicTypeELF   = 6
	magicTypeMachO = 9
)

// Well-known file-type magic byte sequences.
var (
	sigMagicELF      = []byte{0x7F, 0x45, 0x4C, 0x46}
	sigMagicMZ       = []byte{0x4D, 0x5A}
	sigMagicMachO32  = []byte{0xCE, 0xFA, 0xED, 0xFE}
	sigMagicMachO64  = []byte{0xCF, 0xFA, 0xED, 0xFE}
	sigMagicMachO32B = []byte{0xFE, 0xED, 0xFA, 0xCE}
	sigMagicMachO64B = []byte{0xFE, 0xED, 0xFA, 0xCF}
)

// detectMagicType classifies the leading bytes of content into a magicType.
func detectMagicType(content []byte) int {
	if len(content) < 2 {
		return magicTypeAny
	}

	if len(content) >= 4 && bytes.HasPrefix(content, sigMagicELF) {
		return magicTypeELF
	}

	if bytes.HasPrefix(content, sigMagicMZ) {
		return magicTypePE
	}

	if len(content) >= 4 {
		prefix4 := content[:4]
		if bytes.Equal(prefix4, sigMagicMachO32) || bytes.Equal(prefix4, sigMagicMachO64) ||
			bytes.Equal(prefix4, sigMagicMachO32B) || bytes.Equal(prefix4, sigMagicMachO64B) {
			return magicTypeMachO
		}
	}

	return magicTypeAny
}

// isNativeExecutable reports whether the magic type is ELF or Mach-O.
func isNativeExecutable(magicType int) bool {
	return magicType == magicTypeELF || magicType == magicTypeMachO
}

// unixTargetedPrefixes are signature name prefixes denoting Unix-targeted threats.
var unixTargetedPrefixes = []string{
	"Unix.",
	"Linux.",
	"Osx.",
	"MacOS.",
	"ELF.",
	"Mach-O.",
}

// isUnixTargetedSig reports whether the signature name begins with a Unix-targeted prefix.
func isUnixTargetedSig(name string) bool {
	for _, prefix := range unixTargetedPrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}
