package ntfs

import (
	"encoding/binary"
	"testing"
)

func TestParseBootSectorExtractsNtfsGeometry(t *testing.T) {
	sector := make([]byte, 512)
	copy(sector[3:11], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(sector[11:13], 512)
	sector[13] = 8
	binary.LittleEndian.PutUint64(sector[48:56], 4)
	binary.LittleEndian.PutUint64(sector[56:64], 8)
	sector[64] = 246

	got, err := ParseBootSector(sector)
	if err != nil {
		t.Fatalf("ParseBootSector() error = %v", err)
	}
	if got.BytesPerSector != 512 {
		t.Fatalf("expected bytes per sector 512, got %d", got.BytesPerSector)
	}
	if got.SectorsPerCluster != 8 {
		t.Fatalf("expected sectors per cluster 8, got %d", got.SectorsPerCluster)
	}
	if got.ClusterSize != 4096 {
		t.Fatalf("expected cluster size 4096, got %d", got.ClusterSize)
	}
	if got.MFTStartLCN != 4 {
		t.Fatalf("expected MFT start 4, got %d", got.MFTStartLCN)
	}
	if got.MFTMirrorStartLCN != 8 {
		t.Fatalf("expected MFT mirror start 8, got %d", got.MFTMirrorStartLCN)
	}
	if got.FileRecordSize != 1024 {
		t.Fatalf("expected file record size 1024, got %d", got.FileRecordSize)
	}
}

func TestParseBootSectorRejectsInvalidSignature(t *testing.T) {
	sector := make([]byte, 512)
	copy(sector[3:11], []byte("FAT32   "))

	if _, err := ParseBootSector(sector); err == nil {
		t.Fatal("expected invalid signature error, got nil")
	}
}
