package ntfs

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestParseRecordPreservesFileNameTimestampsWhenStandardInformationMissing(t *testing.T) {
	fnTime := time.Date(2026, time.April, 25, 8, 9, 10, 0, time.UTC)
	record := buildTestRecord(testRecordSpec{
		entryNumber: 90,
		sequence:    1,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "fn-only.txt",
		namespace:   1,
		realSize:    32,
		allocSize:   4096,
		modifiedAt:  fnTime,
	})

	zeroStandardInformationTimes(record)

	got, err := ParseRecord(record, 90)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}
	if !got.StandardInformation.CreatedAt.IsZero() || !got.StandardInformation.ModifiedAt.IsZero() || !got.StandardInformation.AccessedAt.IsZero() || !got.StandardInformation.ChangedAt.IsZero() {
		t.Fatalf("expected SI timestamps to remain zero, got %#v", got.StandardInformation)
	}
	if !got.FileName.CreatedAt.Equal(fnTime) {
		t.Fatalf("expected FN createdAt %s, got %s", fnTime, got.FileName.CreatedAt)
	}
	if !got.FileName.ModifiedAt.Equal(fnTime) {
		t.Fatalf("expected FN modifiedAt %s, got %s", fnTime, got.FileName.ModifiedAt)
	}
	if !got.FileName.AccessedAt.Equal(fnTime) {
		t.Fatalf("expected FN accessedAt %s, got %s", fnTime, got.FileName.AccessedAt)
	}
	if !got.FileName.ChangedAt.Equal(fnTime) {
		t.Fatalf("expected FN changedAt %s, got %s", fnTime, got.FileName.ChangedAt)
	}
}

func TestParseRecordPreservesStandardInformationTimestampsWhenFileNameMissing(t *testing.T) {
	siTime := time.Date(2026, time.April, 25, 10, 11, 12, 0, time.UTC)
	record := buildTestRecord(testRecordSpec{
		entryNumber: 91,
		sequence:    1,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "si-only.txt",
		namespace:   1,
		realSize:    64,
		allocSize:   4096,
		modifiedAt:  siTime,
	})

	zeroFileNameTimes(record)

	got, err := ParseRecord(record, 91)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}
	if !got.StandardInformation.CreatedAt.Equal(siTime) {
		t.Fatalf("expected SI createdAt %s, got %s", siTime, got.StandardInformation.CreatedAt)
	}
	if !got.StandardInformation.ModifiedAt.Equal(siTime) {
		t.Fatalf("expected SI modifiedAt %s, got %s", siTime, got.StandardInformation.ModifiedAt)
	}
	if !got.StandardInformation.AccessedAt.Equal(siTime) {
		t.Fatalf("expected SI accessedAt %s, got %s", siTime, got.StandardInformation.AccessedAt)
	}
	if !got.StandardInformation.ChangedAt.Equal(siTime) {
		t.Fatalf("expected SI changedAt %s, got %s", siTime, got.StandardInformation.ChangedAt)
	}
	if !got.FileName.CreatedAt.IsZero() || !got.FileName.ModifiedAt.IsZero() || !got.FileName.AccessedAt.IsZero() || !got.FileName.ChangedAt.IsZero() {
		t.Fatalf("expected FN timestamps to remain zero, got %#v", got.FileName)
	}
}

func zeroStandardInformationTimes(record []byte) {
	zeroResidentAttributeTimes(record, attrTypeStandardInformation, 0x00, 0x08, 0x10, 0x18)
}

func zeroFileNameTimes(record []byte) {
	zeroResidentAttributeTimes(record, attrTypeFileName, 0x08, 0x10, 0x18, 0x20)
}

func zeroResidentAttributeTimes(record []byte, attrType uint32, offsets ...int) {
	attrOffset := int(binary.LittleEndian.Uint16(record[20:22]))
	for offset := attrOffset; offset+8 <= len(record); {
		currentType := binary.LittleEndian.Uint32(record[offset : offset+4])
		if currentType == 0xffffffff {
			return
		}

		attrLength := int(binary.LittleEndian.Uint32(record[offset+4 : offset+8]))
		if attrLength <= 0 || offset+attrLength > len(record) {
			return
		}

		if currentType == attrType && record[offset+8] == 0 {
			valueLength := int(binary.LittleEndian.Uint32(record[offset+16 : offset+20]))
			valueOffset := int(binary.LittleEndian.Uint16(record[offset+20 : offset+22]))
			valueStart := offset + valueOffset
			valueEnd := valueStart + valueLength
			if valueOffset <= 0 || valueStart < offset || valueEnd > offset+attrLength {
				return
			}
			for _, relative := range offsets {
				binary.LittleEndian.PutUint64(record[valueStart+relative:valueStart+relative+8], 0)
			}
			return
		}

		offset += attrLength
	}
}
