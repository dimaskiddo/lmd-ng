package scanner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
)

const (
	peSignatureOffset = 0x3C
	peSignatureSize   = 4
	coffHeaderSize    = 20
	sectionHeaderSize = 40
)

// PESection represents a parsed PE section with its hashes.
type PESection struct {
	Name        string
	Size        int64
	Offset      int64
	VirtualSize int64
	MD5         string
	SHA1        string
	SHA256      string
}

// ParsePESections reads a PE file and returns section info with precomputed hashes.
func ParsePESections(r io.ReadSeeker) ([]PESection, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to DOS header: %w", err)
	}

	var e_lfanew uint32
	if _, err := r.Seek(peSignatureOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to e_lfanew: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &e_lfanew); err != nil {
		return nil, fmt.Errorf("failed to read e_lfanew: %w", err)
	}

	if e_lfanew < 64 || e_lfanew > 1024 {
		return nil, fmt.Errorf("invalid PE signature offset: %d", e_lfanew)
	}

	if _, err := r.Seek(int64(e_lfanew), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to PE signature: %w", err)
	}

	var peSig [peSignatureSize]byte
	if _, err := io.ReadFull(r, peSig[:]); err != nil {
		return nil, fmt.Errorf("failed to read PE signature: %w", err)
	}

	if peSig[0] != 'P' || peSig[1] != 'E' || peSig[2] != 0 || peSig[3] != 0 {
		return nil, fmt.Errorf("invalid PE signature: %x", peSig)
	}

	coffOffset := int64(e_lfanew) + peSignatureSize

	var machine uint16
	var numberOfSections uint16
	var sizeOfOptionalHeader uint16

	if _, err := r.Seek(coffOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to COFF header: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &machine); err != nil {
		return nil, fmt.Errorf("failed to read machine type: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &numberOfSections); err != nil {
		return nil, fmt.Errorf("failed to read number of sections: %w", err)
	}

	if _, err := r.Seek(12, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("failed to skip COFF fields: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &sizeOfOptionalHeader); err != nil {
		return nil, fmt.Errorf("failed to read size of optional header: %w", err)
	}

	if numberOfSections == 0 || numberOfSections > 96 {
		return nil, fmt.Errorf("invalid number of sections: %d", numberOfSections)
	}

	sectionsOffset := coffOffset + coffHeaderSize + int64(sizeOfOptionalHeader)

	sections := make([]PESection, 0, numberOfSections)
	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionsOffset + int64(i)*sectionHeaderSize
		section, err := parseSectionHeader(r, sectionOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse section %d: %w", i, err)
		}

		sections = append(sections, section)
	}

	for i := range sections {
		if err := hashSection(r, &sections[i]); err != nil {
			continue
		}
	}

	return sections, nil
}

// parseSectionHeader reads a PE section header.
func parseSectionHeader(r io.ReadSeeker, offset int64) (PESection, error) {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return PESection{}, err
	}

	var nameRaw [8]byte
	if _, err := io.ReadFull(r, nameRaw[:]); err != nil {
		return PESection{}, fmt.Errorf("failed to read section name: %w", err)
	}

	var virtualSize uint32
	var virtualAddress uint32
	var sizeOfRawData uint32
	var pointerToRawData uint32

	if err := binary.Read(r, binary.LittleEndian, &virtualSize); err != nil {
		return PESection{}, fmt.Errorf("failed to read virtual size: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &virtualAddress); err != nil {
		return PESection{}, fmt.Errorf("failed to read virtual address: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &sizeOfRawData); err != nil {
		return PESection{}, fmt.Errorf("failed to read raw data size: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &pointerToRawData); err != nil {
		return PESection{}, fmt.Errorf("failed to read pointer to raw data: %w", err)
	}

	name := ""
	for _, b := range nameRaw {
		if b == 0 {
			break
		}
		name += string(b)
	}

	return PESection{
		Name:        name,
		Size:        int64(sizeOfRawData),
		Offset:      int64(pointerToRawData),
		VirtualSize: int64(virtualSize),
	}, nil
}

// zeroReader is an io.Reader that always returns zero bytes, for hashing
// zero-filled PE sections (e.g. .bss).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// hashSection reads section data and computes its MD5, SHA1, and SHA256 hashes.
func hashSection(r io.ReadSeeker, section *PESection) error {
	if section.Offset == 0 && section.Size == 0 {
		if section.VirtualSize > 0 {
			zeroSize := section.VirtualSize
			if zeroSize > 128*1024*1024 {
				zeroSize = 128 * 1024 * 1024
			}

			hashZeroSection(section, zeroSize)
		}

		return nil
	}

	if section.Offset == 0 {
		return nil
	}

	if _, err := r.Seek(section.Offset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to section data: %w", err)
	}

	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()

	multiWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	n, err := io.CopyN(multiWriter, r, section.Size)
	if err != nil {
		return fmt.Errorf("failed to read section data: %w", err)
	}

	if n != section.Size {
		return fmt.Errorf("short read: got %d bytes, expected %d", n, section.Size)
	}

	section.MD5 = hashToHex(md5Hasher)
	section.SHA1 = hashToHex(sha1Hasher)
	section.SHA256 = hashToHex(sha256Hasher)

	return nil
}

// hashZeroSection hashes size zero-bytes and stores them in the section.
func hashZeroSection(section *PESection, size int64) {
	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()

	multiWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)
	io.CopyN(multiWriter, zeroReader{}, size)

	section.MD5 = hashToHex(md5Hasher)
	section.SHA1 = hashToHex(sha1Hasher)
	section.SHA256 = hashToHex(sha256Hasher)
}

// hashToHex converts a hash.Hash to a lowercase hex string.
func hashToHex(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}
