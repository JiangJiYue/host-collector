package ntfs

import (
	"encoding/binary"
	"fmt"
)

type BootSector struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	ClusterSize       int64
	MFTStartLCN       int64
	MFTMirrorStartLCN int64
	FileRecordSize    int64
}

func ParseBootSector(sector []byte) (BootSector, error) {
	if len(sector) < 90 {
		return BootSector{}, fmt.Errorf("boot sector too small: %d", len(sector))
	}
	if string(sector[3:11]) != "NTFS    " {
		return BootSector{}, fmt.Errorf("unsupported filesystem signature")
	}

	bytesPerSector := binary.LittleEndian.Uint16(sector[11:13])
	sectorsPerCluster := sector[13]
	clusterSize := int64(bytesPerSector) * int64(sectorsPerCluster)
	if bytesPerSector == 0 || sectorsPerCluster == 0 || clusterSize <= 0 {
		return BootSector{}, fmt.Errorf("invalid NTFS geometry")
	}

	fileRecordSize, err := decodeRecordSize(sector[64], clusterSize)
	if err != nil {
		return BootSector{}, err
	}

	return BootSector{
		BytesPerSector:    bytesPerSector,
		SectorsPerCluster: sectorsPerCluster,
		ClusterSize:       clusterSize,
		MFTStartLCN:       int64(binary.LittleEndian.Uint64(sector[48:56])),
		MFTMirrorStartLCN: int64(binary.LittleEndian.Uint64(sector[56:64])),
		FileRecordSize:    fileRecordSize,
	}, nil
}

func decodeRecordSize(raw byte, clusterSize int64) (int64, error) {
	signed := int8(raw)
	if signed < 0 {
		shift := -signed
		if shift > 30 {
			return 0, fmt.Errorf("file record size shift out of range: %d", shift)
		}
		return int64(1) << shift, nil
	}
	if signed == 0 {
		return 0, fmt.Errorf("file record size cannot be zero")
	}
	return int64(signed) * clusterSize, nil
}
