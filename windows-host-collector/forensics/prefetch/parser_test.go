package prefetch

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseWindows10PrefetchHeader(t *testing.T) {
	data := make([]byte, 0xe0)
	binary.LittleEndian.PutUint32(data[0x00:0x04], 30)
	copy(data[0x04:0x08], []byte("SCCA"))
	binary.LittleEndian.PutUint32(data[0x0c:0x10], 4096)
	copy(data[0x10:0x10+len("POWERSHELL.EXE")*2], utf16le("POWERSHELL.EXE"))
	binary.LittleEndian.PutUint32(data[0x4c:0x50], 0x1234abcd)
	binary.LittleEndian.PutUint32(data[0x64:0x68], 0xe0)
	fileStrings := utf16le("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\x00C:\\Windows\\System32\\kernel32.dll\x00")
	binary.LittleEndian.PutUint32(data[0x68:0x6c], uint32(len(fileStrings)))
	binary.LittleEndian.PutUint64(data[0x80:0x88], 133326432000000000)
	binary.LittleEndian.PutUint64(data[0x88:0x90], 133325568000000000)
	binary.LittleEndian.PutUint32(data[0xd0:0xd4], 7)
	data = append(data, fileStrings...)

	parsed, err := Parse(data, "POWERSHELL.EXE-1234ABCD.pf")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if parsed.FormatVersion != 30 {
		t.Fatalf("expected format version 30, got %d", parsed.FormatVersion)
	}
	if parsed.Signature != "SCCA" {
		t.Fatalf("expected SCCA signature, got %q", parsed.Signature)
	}
	if parsed.ExecutableName != "POWERSHELL.EXE" {
		t.Fatalf("expected executable name from header, got %q", parsed.ExecutableName)
	}
	if len(parsed.ReferencedFiles) != 2 {
		t.Fatalf("expected referenced files from filename strings, got %#v", parsed.ReferencedFiles)
	}
	if parsed.ExecutablePath != "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" {
		t.Fatalf("expected executable path from filename strings, got %q", parsed.ExecutablePath)
	}
	if parsed.FileHash != "1234ABCD" {
		t.Fatalf("expected filename hash, got %q", parsed.FileHash)
	}
	if parsed.RunCount != 7 {
		t.Fatalf("expected run count 7, got %d", parsed.RunCount)
	}
	if len(parsed.RunTimes) != 2 {
		t.Fatalf("expected two parsed run times, got %#v", parsed.RunTimes)
	}
	if parsed.LastRunTime != "2023-07-01T00:00:00Z" {
		t.Fatalf("expected latest FILETIME converted to UTC ISO, got %q", parsed.LastRunTime)
	}
}

func TestParseRejectsUnsupportedSignature(t *testing.T) {
	data := make([]byte, 0x90)
	binary.LittleEndian.PutUint32(data[0x00:0x04], 30)
	copy(data[0x04:0x08], []byte("BAD!"))

	if _, err := Parse(data, "CMD.EXE-11111111.pf"); err == nil {
		t.Fatal("expected invalid signature error")
	}
}

func TestParseDecompressesMAMWrappedPrefetchBeforeParsing(t *testing.T) {
	plain := minimalPrefetchFixture(30, 0xd4)
	binary.LittleEndian.PutUint64(plain[0x80:0x88], 133326432000000000)
	binary.LittleEndian.PutUint32(plain[0xd0:0xd4], 9)

	compressedPayload := []byte("compressed-prefetch-bytes")
	mam := make([]byte, 8+len(compressedPayload))
	copy(mam[0:4], []byte{'M', 'A', 'M', 0x04})
	binary.LittleEndian.PutUint32(mam[4:8], uint32(len(plain)))
	copy(mam[8:], compressedPayload)

	original := decompressMAMPayload
	defer func() { decompressMAMPayload = original }()
	decompressMAMPayload = func(payload []byte, expectedSize uint32) ([]byte, error) {
		if string(payload) != string(compressedPayload) {
			t.Fatalf("unexpected compressed payload: %q", payload)
		}
		if expectedSize != uint32(len(plain)) {
			t.Fatalf("expected uncompressed size %d, got %d", len(plain), expectedSize)
		}
		return plain, nil
	}

	parsed, err := Parse(mam, "CMD.EXE-AABBCCDD.pf")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if parsed.FormatVersion != 30 || parsed.RunCount != 9 || parsed.Signature != "SCCA" {
		t.Fatalf("expected decompressed SCCA payload to be parsed, got %#v", parsed)
	}
}

func TestParseReportsMAMDecompressionFailure(t *testing.T) {
	mam := make([]byte, 12)
	copy(mam[0:4], []byte{'M', 'A', 'M', 0x04})
	binary.LittleEndian.PutUint32(mam[4:8], 4096)

	original := decompressMAMPayload
	defer func() { decompressMAMPayload = original }()
	decompressMAMPayload = func(_ []byte, _ uint32) ([]byte, error) {
		return nil, errors.New("xpress huffman unavailable")
	}

	if _, err := Parse(mam, "CMD.EXE-AABBCCDD.pf"); err == nil || !errors.Is(err, ErrCompressedPrefetch) {
		t.Fatalf("expected compressed prefetch error, got %v", err)
	}
}

func TestParseSupportedPrefetchVersions(t *testing.T) {
	cases := []struct {
		name      string
		version   uint32
		timeAt    int
		countAt   int
		slots     int
		runCount  uint32
		wantTime  string
		wantCount int
	}{
		{name: "windows xp 2003 version 17", version: 17, timeAt: 0x78, countAt: 0x90, slots: 1, runCount: 3, wantTime: "2023-07-01T00:00:00Z", wantCount: 3},
		{name: "windows 7 2008 r2 version 23", version: 23, timeAt: 0x80, countAt: 0x98, slots: 1, runCount: 4, wantTime: "2023-07-01T00:00:00Z", wantCount: 4},
		{name: "windows 8 2012 version 26", version: 26, timeAt: 0x80, countAt: 0xd0, slots: 8, runCount: 5, wantTime: "2023-07-01T00:00:00Z", wantCount: 5},
		{name: "windows 10 2016 plus version 30", version: 30, timeAt: 0x80, countAt: 0xd0, slots: 8, runCount: 6, wantTime: "2023-07-01T00:00:00Z", wantCount: 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := minimalPrefetchFixture(tc.version, tc.countAt+4)
			binary.LittleEndian.PutUint64(data[tc.timeAt:tc.timeAt+8], 133326432000000000)
			if tc.slots > 1 {
				binary.LittleEndian.PutUint64(data[tc.timeAt+8:tc.timeAt+16], 133325568000000000)
			}
			binary.LittleEndian.PutUint32(data[tc.countAt:tc.countAt+4], tc.runCount)

			parsed, err := Parse(data, "CMD.EXE-AABBCCDD.pf")
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if parsed.FormatVersion != int(tc.version) {
				t.Fatalf("expected format version %d, got %d", tc.version, parsed.FormatVersion)
			}
			if parsed.RunCount != tc.wantCount {
				t.Fatalf("expected run count %d, got %d", tc.wantCount, parsed.RunCount)
			}
			if parsed.LastRunTime != tc.wantTime {
				t.Fatalf("expected latest run time %q, got %q", tc.wantTime, parsed.LastRunTime)
			}
		})
	}
}

func minimalPrefetchFixture(version uint32, size int) []byte {
	if size < 0x90 {
		size = 0x90
	}
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data[0x00:0x04], version)
	copy(data[0x04:0x08], []byte("SCCA"))
	binary.LittleEndian.PutUint32(data[0x0c:0x10], uint32(size))
	copy(data[0x10:0x10+len("CMD.EXE")*2], utf16le("CMD.EXE"))
	binary.LittleEndian.PutUint32(data[0x4c:0x50], 0xaabbccdd)
	return data
}

func utf16le(value string) []byte {
	out := make([]byte, len(value)*2)
	for i, r := range value {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], uint16(r))
	}
	return out
}
