package prefetch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	signatureSCCA = "SCCA"
)

var (
	ErrTooSmall           = errors.New("prefetch data too small")
	ErrInvalidSignature   = errors.New("invalid prefetch signature")
	ErrCompressedPrefetch = errors.New("compressed prefetch requires decompression")
	ErrUnsupportedFormat  = errors.New("unsupported prefetch format version")
)

type ParsedPrefetch struct {
	FormatVersion   int
	Signature       string
	ExecutableName  string
	ExecutablePath  string
	FileHash        string
	EmbeddedHash    string
	FileSize        uint32
	RunCount        int
	LastRunTime     string
	RunTimes        []string
	ReferencedFiles []string
}

type layout struct {
	runTimeOffset  int
	runTimeSlots   int
	runCountOffset int
}

var layouts = map[uint32]layout{
	17: {runTimeOffset: 0x78, runTimeSlots: 1, runCountOffset: 0x90},
	23: {runTimeOffset: 0x80, runTimeSlots: 1, runCountOffset: 0x98},
	26: {runTimeOffset: 0x80, runTimeSlots: 8, runCountOffset: 0xd0},
	30: {runTimeOffset: 0x80, runTimeSlots: 8, runCountOffset: 0xd0},
}

func Parse(data []byte, evidenceName string) (ParsedPrefetch, error) {
	if isMAMCompressedPrefetch(data) {
		uncompressed, err := decompressMAMPayload(data[8:], binary.LittleEndian.Uint32(data[4:8]))
		if err != nil {
			return ParsedPrefetch{}, fmt.Errorf("%w: %v", ErrCompressedPrefetch, err)
		}
		data = uncompressed
	}
	if len(data) < 0x54 {
		return ParsedPrefetch{}, ErrTooSmall
	}

	version := binary.LittleEndian.Uint32(data[0x00:0x04])
	signature := string(data[0x04:0x08])
	if signature != signatureSCCA {
		return ParsedPrefetch{}, ErrInvalidSignature
	}

	pfLayout, ok := layouts[version]
	if !ok {
		return ParsedPrefetch{}, fmt.Errorf("%w: %d", ErrUnsupportedFormat, version)
	}
	if len(data) < pfLayout.runCountOffset+4 {
		return ParsedPrefetch{}, ErrTooSmall
	}

	runTimes := parseRunTimes(data, pfLayout)
	referencedFiles := parseReferencedFiles(data)
	executableName := readUTF16String(data[0x10:0x4c])
	embeddedHash := fmt.Sprintf("%08X", binary.LittleEndian.Uint32(data[0x4c:0x50]))
	fileHash := hashFromFilename(evidenceName)
	if fileHash == "" {
		fileHash = embeddedHash
	}

	return ParsedPrefetch{
		FormatVersion:   int(version),
		Signature:       signature,
		ExecutableName:  executableName,
		ExecutablePath:  findExecutablePath(executableName, referencedFiles),
		FileHash:        fileHash,
		EmbeddedHash:    embeddedHash,
		FileSize:        binary.LittleEndian.Uint32(data[0x0c:0x10]),
		RunCount:        int(binary.LittleEndian.Uint32(data[pfLayout.runCountOffset : pfLayout.runCountOffset+4])),
		LastRunTime:     latestTime(runTimes),
		RunTimes:        runTimes,
		ReferencedFiles: referencedFiles,
	}, nil
}

func isMAMCompressedPrefetch(data []byte) bool {
	return len(data) >= 8 && data[0] == 'M' && data[1] == 'A' && data[2] == 'M'
}

func parseRunTimes(data []byte, pfLayout layout) []string {
	runTimes := make([]string, 0, pfLayout.runTimeSlots)
	for slot := 0; slot < pfLayout.runTimeSlots; slot++ {
		offset := pfLayout.runTimeOffset + slot*8
		if len(data) < offset+8 {
			break
		}
		if value := filetimeToISOString(binary.LittleEndian.Uint64(data[offset : offset+8])); value != "" {
			runTimes = append(runTimes, value)
		}
	}
	return runTimes
}

func latestTime(values []string) string {
	if len(values) == 0 {
		return ""
	}
	latest := values[0]
	for _, value := range values[1:] {
		if value > latest {
			latest = value
		}
	}
	return latest
}

func filetimeToISOString(filetime uint64) string {
	if filetime == 0 {
		return ""
	}
	const ticksBetweenWindowsAndUnixEpoch = 116444736000000000
	if filetime <= ticksBetweenWindowsAndUnixEpoch {
		return ""
	}
	unixNanos := int64(filetime-ticksBetweenWindowsAndUnixEpoch) * 100
	return time.Unix(0, unixNanos).UTC().Format(time.RFC3339)
}

func readUTF16String(data []byte) string {
	chars := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		value := binary.LittleEndian.Uint16(data[index : index+2])
		if value == 0 {
			break
		}
		chars = append(chars, value)
	}
	return strings.TrimSpace(string(utf16.Decode(chars)))
}

func parseReferencedFiles(data []byte) []string {
	if len(data) < 0x6c {
		return nil
	}
	offset := int(binary.LittleEndian.Uint32(data[0x64:0x68]))
	length := int(binary.LittleEndian.Uint32(data[0x68:0x6c]))
	if offset <= 0 || length <= 0 || offset >= len(data) {
		return nil
	}
	end := offset + length
	if end > len(data) {
		end = len(data)
	}

	entries := make([]string, 0)
	for _, value := range strings.Split(readUTF16StringBlock(data[offset:end]), "\x00") {
		value = strings.TrimSpace(value)
		if value != "" {
			entries = append(entries, value)
		}
	}
	return entries
}

func readUTF16StringBlock(data []byte) string {
	chars := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		chars = append(chars, binary.LittleEndian.Uint16(data[index:index+2]))
	}
	return string(utf16.Decode(chars))
}

func findExecutablePath(executableName string, referencedFiles []string) string {
	target := strings.ToLower(strings.TrimSuffix(executableName, ".EXE"))
	for _, path := range referencedFiles {
		base := strings.ToLower(crossPlatformBase(path))
		if base == strings.ToLower(executableName) || strings.TrimSuffix(base, ".exe") == target {
			return path
		}
	}
	return ""
}

func crossPlatformBase(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	return filepath.Base(value)
}

func hashFromFilename(name string) string {
	base := filepath.Base(name)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	parts := strings.Split(base, "-")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToUpper(parts[len(parts)-1])
}
