package ntfs

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func TestParseRecordExtractsFileNameAndTimestamps(t *testing.T) {
	modifiedAt := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	record := buildTestRecord(testRecordSpec{
		entryNumber: 42,
		sequence:    7,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "note.txt",
		namespace:   1,
		realSize:    123,
		allocSize:   4096,
		modifiedAt:  modifiedAt,
	})

	got, err := ParseRecord(record, 42)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}
	if got.EntryNumber != 42 {
		t.Fatalf("expected entry number 42, got %d", got.EntryNumber)
	}
	if got.SequenceNumber != 7 {
		t.Fatalf("expected sequence 7, got %d", got.SequenceNumber)
	}
	if !got.IsAllocated {
		t.Fatal("expected allocated record")
	}
	if got.IsDirectory {
		t.Fatal("expected regular file record")
	}
	if got.FileName.Name != "note.txt" {
		t.Fatalf("expected note.txt, got %q", got.FileName.Name)
	}
	if got.FileName.ParentMFTEntry != 5 {
		t.Fatalf("expected parent entry 5, got %d", got.FileName.ParentMFTEntry)
	}
	if got.FileName.RealSize != 123 {
		t.Fatalf("expected real size 123, got %d", got.FileName.RealSize)
	}
	if got.StandardInformation.ModifiedAt.IsZero() {
		t.Fatal("expected modified timestamp to be populated")
	}
	if !got.StandardInformation.ModifiedAt.Equal(modifiedAt) {
		t.Fatalf("expected modifiedAt %s, got %s", modifiedAt, got.StandardInformation.ModifiedAt)
	}
}

func TestParseRecordMarksDirectoryFromFlags(t *testing.T) {
	record := buildTestRecord(testRecordSpec{
		entryNumber: 10,
		sequence:    2,
		flags:       0x0003,
		parentEntry: 5,
		parentSeq:   1,
		name:        "Users",
		namespace:   1,
		realSize:    0,
		allocSize:   0,
		modifiedAt:  time.Date(2024, time.February, 3, 4, 5, 6, 0, time.UTC),
	})

	got, err := ParseRecord(record, 10)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}
	if !got.IsDirectory {
		t.Fatal("expected directory flag to be set")
	}
}

func TestParseRecordReturnsErrorForTruncatedResidentAttributeHeader(t *testing.T) {
	record := buildTestRecord(testRecordSpec{
		entryNumber: 13,
		sequence:    1,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "bad.txt",
		namespace:   1,
		realSize:    1,
		allocSize:   1024,
		modifiedAt:  time.Date(2024, time.March, 4, 5, 6, 7, 0, time.UTC),
	})
	binary.LittleEndian.PutUint32(record[0x38+4:0x38+8], 20)

	if _, err := ParseRecord(record, 13); err == nil {
		t.Fatal("expected truncated resident attribute header error, got nil")
	}
}

func TestParseRecordWithBytesPerSectorSupportsNon512Fixup(t *testing.T) {
	modifiedAt := time.Date(2024, time.April, 5, 6, 7, 8, 0, time.UTC)
	record := buildTestRecordWithSectorSize(testRecordSpec{
		entryNumber: 77,
		sequence:    4,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "sector.bin",
		namespace:   1,
		realSize:    64,
		allocSize:   4096,
		modifiedAt:  modifiedAt,
	}, 256)

	got, err := ParseRecordWithSectorSize(record, 77, 256)
	if err != nil {
		t.Fatalf("ParseRecordWithSectorSize() error = %v", err)
	}
	if got.FileName.Name != "sector.bin" {
		t.Fatalf("expected sector.bin, got %q", got.FileName.Name)
	}
}

func TestParseRecordPrefersWin32FileNameNamespace(t *testing.T) {
	record := buildTestRecordWithFileNames(testRecordSpec{
		entryNumber: 88,
		sequence:    5,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "ignored.txt",
		namespace:   2,
		realSize:    10,
		allocSize:   1024,
		modifiedAt:  time.Date(2024, time.May, 6, 7, 8, 9, 0, time.UTC),
	}, []fileNameSpec{
		{name: "IGNORED~1.TXT", namespace: 2},
		{name: "ignored.txt", namespace: 1},
	})

	got, err := ParseRecord(record, 88)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}
	if got.FileName.Name != "ignored.txt" {
		t.Fatalf("expected Win32 name to win, got %q", got.FileName.Name)
	}
	if got.FileName.NameNamespace != 1 {
		t.Fatalf("expected Win32 namespace 1, got %d", got.FileName.NameNamespace)
	}
}

func TestFiletimeToTimeReturnsZeroWhenValuePrecedesUnixEpochOffset(t *testing.T) {
	const beforeUnixEpochOffset = 1

	got := filetimeToTime(beforeUnixEpochOffset)
	if !got.IsZero() {
		t.Fatalf("expected zero time for pre-epoch FILETIME, got %s", got)
	}
}

type testRecordSpec struct {
	entryNumber int64
	sequence    uint16
	flags       uint16
	parentEntry int64
	parentSeq   uint16
	name        string
	namespace   uint8
	realSize    int64
	allocSize   int64
	modifiedAt  time.Time
}

type fileNameSpec struct {
	name      string
	namespace uint8
}

func buildTestRecord(spec testRecordSpec) []byte {
	return buildTestRecordWithSectorSize(spec, 512)
}

func buildTestRecordWithSectorSize(spec testRecordSpec, bytesPerSector int) []byte {
	record := make([]byte, 1024)
	return fillTestRecord(record, spec, bytesPerSector, []fileNameSpec{
		{name: spec.name, namespace: spec.namespace},
	})
}

func buildTestRecordWithFileNames(spec testRecordSpec, names []fileNameSpec) []byte {
	record := make([]byte, 1024)
	return fillTestRecord(record, spec, 512, names)
}

func fillTestRecord(record []byte, spec testRecordSpec, bytesPerSector int, names []fileNameSpec) []byte {
	copy(record[0:4], []byte("FILE"))

	usaCount := uint16(len(record)/bytesPerSector + 1)
	binary.LittleEndian.PutUint16(record[4:6], 0x30)
	binary.LittleEndian.PutUint16(record[6:8], usaCount)
	binary.LittleEndian.PutUint16(record[16:18], spec.sequence)
	binary.LittleEndian.PutUint16(record[20:22], 0x38)
	binary.LittleEndian.PutUint16(record[22:24], spec.flags)
	binary.LittleEndian.PutUint32(record[24:28], 1024)
	binary.LittleEndian.PutUint32(record[28:32], 1024)

	usn := uint16(0xaaaa)
	binary.LittleEndian.PutUint16(record[0x30:0x32], usn)
	for i := 1; i < int(usaCount); i++ {
		replacement := uint16(0x1100 + i)
		binary.LittleEndian.PutUint16(record[0x30+i*2:0x32+i*2], replacement)
		sectorEnd := i*bytesPerSector - 2
		binary.LittleEndian.PutUint16(record[sectorEnd:sectorEnd+2], usn)
	}

	offset := 0x38
	offset = writeResidentAttribute(record, offset, 0x10, buildStandardInformationValue(spec.modifiedAt))
	for _, name := range names {
		nameSpec := spec
		nameSpec.name = name.name
		nameSpec.namespace = name.namespace
		offset = writeResidentAttribute(record, offset, 0x30, buildFileNameValue(nameSpec))
	}
	binary.LittleEndian.PutUint32(record[offset:offset+4], 0xffffffff)

	return record
}

func writeResidentAttribute(record []byte, offset int, attrType uint32, value []byte) int {
	headerLength := 24
	totalLength := align8(headerLength + len(value))
	binary.LittleEndian.PutUint32(record[offset:offset+4], attrType)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], uint32(totalLength))
	record[offset+8] = 0
	record[offset+9] = 0
	binary.LittleEndian.PutUint16(record[offset+10:offset+12], 0)
	binary.LittleEndian.PutUint16(record[offset+12:offset+14], 0)
	binary.LittleEndian.PutUint16(record[offset+14:offset+16], 0)
	binary.LittleEndian.PutUint32(record[offset+16:offset+20], uint32(len(value)))
	binary.LittleEndian.PutUint16(record[offset+20:offset+22], uint16(headerLength))
	record[offset+22] = 0
	record[offset+23] = 0
	copy(record[offset+headerLength:offset+headerLength+len(value)], value)
	return offset + totalLength
}

func buildStandardInformationValue(modifiedAt time.Time) []byte {
	value := make([]byte, 0x30)
	filetime := toFiletime(modifiedAt)
	for _, off := range []int{0x00, 0x08, 0x10, 0x18} {
		binary.LittleEndian.PutUint64(value[off:off+8], filetime)
	}
	return value
}

func buildFileNameValue(spec testRecordSpec) []byte {
	nameUTF16 := utf16.Encode([]rune(spec.name))
	value := make([]byte, 0x42+len(nameUTF16)*2)
	parentRef := uint64(spec.parentEntry) | (uint64(spec.parentSeq) << 48)
	binary.LittleEndian.PutUint64(value[0x00:0x08], parentRef)
	filetime := toFiletime(spec.modifiedAt)
	for _, off := range []int{0x08, 0x10, 0x18, 0x20} {
		binary.LittleEndian.PutUint64(value[off:off+8], filetime)
	}
	binary.LittleEndian.PutUint64(value[0x28:0x30], uint64(spec.allocSize))
	binary.LittleEndian.PutUint64(value[0x30:0x38], uint64(spec.realSize))
	binary.LittleEndian.PutUint32(value[0x38:0x3c], uint32(spec.flags))
	value[0x40] = uint8(len(nameUTF16))
	value[0x41] = spec.namespace
	for i, r := range nameUTF16 {
		binary.LittleEndian.PutUint16(value[0x42+i*2:0x44+i*2], r)
	}
	return value
}

func toFiletime(ts time.Time) uint64 {
	const windowsEpochOffset = 116444736000000000
	return uint64(ts.UTC().UnixNano()/100) + windowsEpochOffset
}

func align8(n int) int {
	if n%8 == 0 {
		return n
	}
	return n + (8 - (n % 8))
}
