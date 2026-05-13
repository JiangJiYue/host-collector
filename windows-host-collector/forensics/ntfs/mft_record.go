package ntfs

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

const (
	attrTypeStandardInformation = 0x10
	attrTypeFileName            = 0x30
	attrTypeData                = 0x80
)

type StandardInformation struct {
	CreatedAt  time.Time
	ModifiedAt time.Time
	ChangedAt  time.Time
	AccessedAt time.Time
}

type FileNameAttribute struct {
	ParentMFTEntry int64
	ParentSequence uint16
	Name           string
	NameNamespace  uint8
	AllocatedSize  int64
	RealSize       int64
	CreatedAt      time.Time
	ModifiedAt     time.Time
	ChangedAt      time.Time
	AccessedAt     time.Time
}

type DataRun struct {
	VCNStart       int64
	LengthClusters int64
	LCN            int64
}

type Record struct {
	EntryNumber         int64
	SequenceNumber      uint16
	Flags               uint16
	IsAllocated         bool
	IsDirectory         bool
	StandardInformation StandardInformation
	FileName            FileNameAttribute
	DataRuns            []DataRun
	DataSize            int64
}

func ParseRecord(record []byte, entryNumber int64) (Record, error) {
	return ParseRecordWithSectorSize(record, entryNumber, 512)
}

func ParseRecordWithSectorSize(record []byte, entryNumber int64, bytesPerSector int) (Record, error) {
	if len(record) < 56 {
		return Record{}, fmt.Errorf("record too small: %d", len(record))
	}
	if string(record[0:4]) != "FILE" {
		return Record{}, fmt.Errorf("invalid record signature")
	}
	if bytesPerSector <= 0 {
		return Record{}, fmt.Errorf("invalid bytes per sector %d", bytesPerSector)
	}

	if err := applyUpdateSequenceFixup(record, bytesPerSector); err != nil {
		return Record{}, err
	}

	attrOffset := int(binary.LittleEndian.Uint16(record[20:22]))
	if attrOffset <= 0 || attrOffset >= len(record) {
		return Record{}, fmt.Errorf("invalid attribute offset %d", attrOffset)
	}

	out := Record{
		EntryNumber:    entryNumber,
		SequenceNumber: binary.LittleEndian.Uint16(record[16:18]),
		Flags:          binary.LittleEndian.Uint16(record[22:24]),
	}
	out.IsAllocated = out.Flags&0x0001 != 0
	out.IsDirectory = out.Flags&0x0002 != 0

	for offset := attrOffset; offset+8 <= len(record); {
		attrType := binary.LittleEndian.Uint32(record[offset : offset+4])
		if attrType == 0xffffffff {
			break
		}

		attrLength := int(binary.LittleEndian.Uint32(record[offset+4 : offset+8]))
		if attrLength <= 0 || offset+attrLength > len(record) {
			return Record{}, fmt.Errorf("invalid attribute length %d", attrLength)
		}
		if record[offset+8] != 0 {
			if attrType == attrTypeData {
				runs, dataSize, err := parseNonResidentDataRuns(record[offset : offset+attrLength])
				if err != nil {
					return Record{}, err
				}
				out.DataRuns = append(out.DataRuns, runs...)
				out.DataSize = dataSize
			}
			offset += attrLength
			continue
		}
		if attrLength < residentAttributeHeaderSize {
			return Record{}, fmt.Errorf("resident attribute header too small: %d", attrLength)
		}

		valueLength := int(binary.LittleEndian.Uint32(record[offset+16 : offset+20]))
		valueOffset := int(binary.LittleEndian.Uint16(record[offset+20 : offset+22]))
		valueStart := offset + valueOffset
		valueEnd := valueStart + valueLength
		if valueOffset <= 0 || valueStart < offset || valueEnd > offset+attrLength {
			return Record{}, fmt.Errorf("invalid resident attribute bounds")
		}

		value := record[valueStart:valueEnd]
		switch attrType {
		case attrTypeStandardInformation:
			si, err := parseStandardInformation(value)
			if err != nil {
				return Record{}, err
			}
			out.StandardInformation = si
		case attrTypeFileName:
			fn, err := parseFileNameAttribute(value)
			if err != nil {
				return Record{}, err
			}
			if shouldPreferFileName(fn, out.FileName) {
				out.FileName = fn
			}
		}

		offset += attrLength
	}

	return out, nil
}

const residentAttributeHeaderSize = 24

func applyUpdateSequenceFixup(record []byte, bytesPerSector int) error {
	usaOffset := int(binary.LittleEndian.Uint16(record[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(record[6:8]))
	if usaOffset == 0 || usaCount == 0 {
		return nil
	}
	if usaOffset+usaCount*2 > len(record) {
		return fmt.Errorf("update sequence array outside record")
	}

	usn := binary.LittleEndian.Uint16(record[usaOffset : usaOffset+2])
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*bytesPerSector - 2
		if sectorEnd+2 > len(record) {
			return fmt.Errorf("update sequence sector outside record")
		}
		if binary.LittleEndian.Uint16(record[sectorEnd:sectorEnd+2]) != usn {
			return fmt.Errorf("update sequence mismatch")
		}
		replacementOffset := usaOffset + i*2
		replacement := binary.LittleEndian.Uint16(record[replacementOffset : replacementOffset+2])
		binary.LittleEndian.PutUint16(record[sectorEnd:sectorEnd+2], replacement)
	}
	return nil
}

func shouldPreferFileName(candidate, current FileNameAttribute) bool {
	if current.Name == "" {
		return true
	}
	return fileNamePreference(candidate.NameNamespace) < fileNamePreference(current.NameNamespace)
}

func fileNamePreference(namespace uint8) int {
	switch namespace {
	case 1:
		return 0
	case 3:
		return 1
	case 0:
		return 2
	case 2:
		return 3
	default:
		return 4
	}
}

func parseStandardInformation(value []byte) (StandardInformation, error) {
	if len(value) < 32 {
		return StandardInformation{}, fmt.Errorf("standard information too small")
	}
	return StandardInformation{
		CreatedAt:  filetimeToTime(binary.LittleEndian.Uint64(value[0x00:0x08])),
		ModifiedAt: filetimeToTime(binary.LittleEndian.Uint64(value[0x08:0x10])),
		ChangedAt:  filetimeToTime(binary.LittleEndian.Uint64(value[0x10:0x18])),
		AccessedAt: filetimeToTime(binary.LittleEndian.Uint64(value[0x18:0x20])),
	}, nil
}

func parseFileNameAttribute(value []byte) (FileNameAttribute, error) {
	if len(value) < 0x42 {
		return FileNameAttribute{}, fmt.Errorf("file name attribute too small")
	}
	parentRef := binary.LittleEndian.Uint64(value[0x00:0x08])
	nameLength := int(value[0x40])
	nameBytes := nameLength * 2
	if 0x42+nameBytes > len(value) {
		return FileNameAttribute{}, fmt.Errorf("file name attribute truncated")
	}

	nameUTF16 := make([]uint16, nameLength)
	for i := 0; i < nameLength; i++ {
		nameUTF16[i] = binary.LittleEndian.Uint16(value[0x42+i*2 : 0x44+i*2])
	}

	return FileNameAttribute{
		ParentMFTEntry: int64(parentRef & 0x0000ffffffffffff),
		ParentSequence: uint16(parentRef >> 48),
		Name:           string(utf16.Decode(nameUTF16)),
		NameNamespace:  value[0x41],
		CreatedAt:      filetimeToTime(binary.LittleEndian.Uint64(value[0x08:0x10])),
		ModifiedAt:     filetimeToTime(binary.LittleEndian.Uint64(value[0x10:0x18])),
		ChangedAt:      filetimeToTime(binary.LittleEndian.Uint64(value[0x18:0x20])),
		AccessedAt:     filetimeToTime(binary.LittleEndian.Uint64(value[0x20:0x28])),
		AllocatedSize:  int64(binary.LittleEndian.Uint64(value[0x28:0x30])),
		RealSize:       int64(binary.LittleEndian.Uint64(value[0x30:0x38])),
	}, nil
}

func parseNonResidentDataRuns(attr []byte) ([]DataRun, int64, error) {
	if len(attr) < 64 {
		return nil, 0, fmt.Errorf("non-resident data attribute too small: %d", len(attr))
	}
	runlistOffset := int(binary.LittleEndian.Uint16(attr[32:34]))
	if runlistOffset <= 0 || runlistOffset >= len(attr) {
		return nil, 0, fmt.Errorf("invalid data runlist offset %d", runlistOffset)
	}
	dataSize := int64(binary.LittleEndian.Uint64(attr[48:56]))
	runs, err := parseDataRuns(attr[runlistOffset:])
	return runs, dataSize, err
}

func parseDataRuns(runlist []byte) ([]DataRun, error) {
	runs := make([]DataRun, 0)
	var currentLCN int64
	var currentVCN int64
	for offset := 0; offset < len(runlist); {
		header := runlist[offset]
		offset++
		if header == 0 {
			return runs, nil
		}

		lengthBytes := int(header & 0x0f)
		lcnDeltaBytes := int((header >> 4) & 0x0f)
		if lengthBytes == 0 || lengthBytes > 8 || lcnDeltaBytes > 8 {
			return nil, fmt.Errorf("invalid data run header 0x%x", header)
		}
		if offset+lengthBytes+lcnDeltaBytes > len(runlist) {
			return nil, fmt.Errorf("truncated data run")
		}

		length := readUnsignedLE(runlist[offset : offset+lengthBytes])
		offset += lengthBytes
		lcnDelta := readSignedLE(runlist[offset : offset+lcnDeltaBytes])
		offset += lcnDeltaBytes
		if length <= 0 {
			return nil, fmt.Errorf("invalid data run length %d", length)
		}

		currentLCN += lcnDelta
		runs = append(runs, DataRun{
			VCNStart:       currentVCN,
			LengthClusters: length,
			LCN:            currentLCN,
		})
		currentVCN += length
	}
	return nil, fmt.Errorf("unterminated data runlist")
}

func readUnsignedLE(data []byte) int64 {
	var value int64
	for i, b := range data {
		value |= int64(b) << (8 * i)
	}
	return value
}

func readSignedLE(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	value := readUnsignedLE(data)
	if data[len(data)-1]&0x80 == 0 {
		return value
	}
	return value - (int64(1) << (uint(len(data)) * 8))
}

func filetimeToTime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	const windowsEpochOffset = 116444736000000000
	if v < windowsEpochOffset {
		return time.Time{}
	}
	return time.Unix(0, int64(v-windowsEpochOffset)*100).UTC()
}
