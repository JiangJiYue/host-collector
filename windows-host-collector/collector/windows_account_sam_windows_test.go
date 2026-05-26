//go:build windows

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestParseSAMRIDKeyName(t *testing.T) {
	t.Run("hex rid key", func(t *testing.T) {
		got, ok := parseSAMRIDKeyName("000003EB")
		if !ok {
			t.Fatal("expected RID key to parse")
		}
		if got != 1003 {
			t.Fatalf("expected RID 1003, got %d", got)
		}
	})

	t.Run("names is not rid key", func(t *testing.T) {
		if _, ok := parseSAMRIDKeyName("Names"); ok {
			t.Fatal("expected Names not to parse as a RID key")
		}
	})
}

func TestSAMAccountRecordToSource(t *testing.T) {
	rid := uint32(1003)
	record := samAccountRecord{
		Username:     "hidden_support",
		RID:          rid,
		RIDKey:       true,
		NameIndex:    true,
		NameIndexRID: &rid,
	}

	got := samAccountRecordToSource(record)

	if got.Source != accountSourceSAM {
		t.Fatalf("expected source %q, got %q", accountSourceSAM, got.Source)
	}
	if !got.SAMRidKey {
		t.Fatal("expected SAMRidKey to be true")
	}
	if !got.SAMNameIndex {
		t.Fatal("expected SAMNameIndex to be true")
	}
	if got.RID == nil || *got.RID != 1003 {
		t.Fatalf("expected RID 1003, got %#v", got.RID)
	}
	if got.NameIndexRID == nil || *got.NameIndexRID != 1003 {
		t.Fatalf("expected NameIndexRID 1003, got %#v", got.NameIndexRID)
	}
}

func TestSAMAccountRecordToSourceIncludesSemanticEvidence(t *testing.T) {
	rid := uint32(1003)
	flags := uint32(0x0200)
	record := samAccountRecord{
		Username:         "youzi$",
		RID:              rid,
		RIDKey:           true,
		NameIndex:        true,
		NameIndexRID:     &rid,
		FDigest:          "sha256:f-digest",
		VDigest:          "sha256:v-digest",
		ParsedUsername:   ptr("youzi$"),
		FullName:         ptr("Shadow Admin"),
		Comment:          ptr("from-v"),
		Flags:            &flags,
		AliasMemberships: []string{"Administrators"},
	}

	got := samAccountRecordToSource(record)

	if got.SAM == nil {
		t.Fatal("expected nested sam evidence")
	}
	if got.SAM.FDigest != "sha256:f-digest" || got.SAM.VDigest != "sha256:v-digest" {
		t.Fatalf("expected digests to round-trip, got %#v", got.SAM)
	}
	if got.SAM.ParsedUsername == nil || *got.SAM.ParsedUsername != "youzi$" {
		t.Fatalf("expected parsed username to round-trip, got %#v", got.SAM.ParsedUsername)
	}
	if len(got.SAM.BuiltinAliasMemberships) != 1 || got.SAM.BuiltinAliasMemberships[0] != "Administrators" {
		t.Fatalf("expected alias membership, got %#v", got.SAM.BuiltinAliasMemberships)
	}
	if !got.SAMAliasMembership {
		t.Fatalf("expected sam alias membership visibility")
	}
}

func TestOpenSAMKeyUsesBackupAccessMask(t *testing.T) {
	got := samBackupOpenAccessMask(registry.QUERY_VALUE)
	if got&regsamBackupRead != regsamBackupRead {
		t.Fatalf("expected backup read bits in access mask %#x", got)
	}
	if got&registry.QUERY_VALUE != registry.QUERY_VALUE {
		t.Fatalf("expected requested query value bit in access mask %#x", got)
	}
}

func TestWindowsSAMAccountProviderCollectsLiveEvidenceWhenEnabled(t *testing.T) {
	if os.Getenv("HOST_COLLECTOR_LIVE_SAM_TEST") != "1" {
		t.Skip("set HOST_COLLECTOR_LIVE_SAM_TEST=1 to read live SAM hive")
	}

	records, err := windowsSAMAccountProvider{}.collect(context.Background())
	if err != nil {
		t.Fatalf("collect SAM records: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected at least one SAM account record")
	}
	hasRID500 := false
	for _, record := range records {
		if record.RID != nil && *record.RID == 500 {
			hasRID500 = true
			break
		}
	}
	if !hasRID500 {
		t.Fatalf("expected SAM records to include RID 500, got %#v", records)
	}
}

func TestCombineCleanupError(t *testing.T) {
	mainErr := errors.New("load failed")
	cleanupErr := errors.New("restore failed")

	got := combineCleanupError(mainErr, cleanupErr)
	if got == nil {
		t.Fatal("expected combined error")
	}
	if !errors.Is(got, mainErr) {
		t.Fatalf("expected combined error to match main error, got %v", got)
	}
	if !strings.Contains(got.Error(), cleanupErr.Error()) {
		t.Fatalf("expected combined error to mention cleanup failure, got %q", got.Error())
	}

	got = combineCleanupError(nil, cleanupErr)
	if got == nil {
		t.Fatal("expected cleanup error when main error is nil")
	}
	if !errors.Is(got, cleanupErr) {
		t.Fatalf("expected cleanup-only error to match cleanup error, got %v", got)
	}
}

func TestSAMCleanupWarningDoesNotDiscardSources(t *testing.T) {
	sources, err := samSourcesFromRecordsWithCleanup([]samAccountRecord{
		{Username: "Administrator", RID: 500, RIDKey: true},
	}, errors.New("cleanup failed"))

	if err != nil {
		t.Fatalf("expected cleanup warning not to fail SAM collection, got %v", err)
	}
	if len(sources) != 1 || sources[0].Username != "Administrator" {
		t.Fatalf("expected SAM sources to be preserved, got %#v", sources)
	}
}

func TestParseSAMRIDFromClassString(t *testing.T) {
	t.Run("hex class string", func(t *testing.T) {
		got, ok := parseSAMRIDFromClassString("000003EB")
		if !ok {
			t.Fatal("expected class RID to parse")
		}
		if got != 1003 {
			t.Fatalf("expected RID 1003, got %d", got)
		}
	})

	t.Run("blank class string", func(t *testing.T) {
		if _, ok := parseSAMRIDFromClassString("   "); ok {
			t.Fatal("expected blank class string not to parse")
		}
	})
}

func TestDigestSAMValue(t *testing.T) {
	got := digestSAMValue("sha256:", []byte("sam-value"))
	sum := sha256.Sum256([]byte("sam-value"))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestDigestSAMValueEmpty(t *testing.T) {
	if got := digestSAMValue("sha256:", nil); got != "" {
		t.Fatalf("expected empty digest, got %q", got)
	}
}

func TestMergeAliasMembershipsIntoRecords(t *testing.T) {
	rid := uint32(1003)
	records := []samAccountRecord{
		{Username: "youzi$", RID: rid, RIDKey: true, NameIndex: true, NameIndexRID: &rid},
	}
	bySID := map[string][]string{
		"S-1-5-21-1-2-3-1003": {"Administrators"},
	}

	mergeAliasMemberships(records, bySID, "S-1-5-21-1-2-3")

	if len(records[0].AliasMemberships) != 1 || records[0].AliasMemberships[0] != "Administrators" {
		t.Fatalf("expected administrators alias membership, got %#v", records[0].AliasMemberships)
	}
}

func TestParseSAMVValue(t *testing.T) {
	data := make([]byte, 0xCC+64)
	putSAMVUTF16Field(data, 0x0C, 0x10, 0, "youzi$")
	putSAMVUTF16Field(data, 0x18, 0x1C, 16, "Shadow Admin")
	putSAMVUTF16Field(data, 0x24, 0x28, 48, "from-v")

	got := parseSAMVValue(data)

	if got.Username == nil || *got.Username != "youzi$" {
		t.Fatalf("expected parsed username, got %#v", got.Username)
	}
	if got.FullName == nil || *got.FullName != "Shadow Admin" {
		t.Fatalf("expected parsed full name, got %#v", got.FullName)
	}
	if got.Comment == nil || *got.Comment != "from-v" {
		t.Fatalf("expected parsed comment, got %#v", got.Comment)
	}
}

func TestParseSAMFValue(t *testing.T) {
	data := make([]byte, 80)
	copy(data[8:16], mustFiletimeBytes("2026-04-21T00:00:00Z"))
	binary.LittleEndian.PutUint16(data[56:58], 0x0200)
	binary.LittleEndian.PutUint16(data[64:66], 3)
	binary.LittleEndian.PutUint16(data[66:68], 12)

	got := parseSAMFValue(data)

	if got.Flags == nil || *got.Flags != 0x0200 {
		t.Fatalf("expected flags 0x0200, got %#v", got.Flags)
	}
	if got.LastLogon == nil || *got.LastLogon != "2026-04-21T00:00:00Z" {
		t.Fatalf("expected last logon, got %#v", got.LastLogon)
	}
	if got.LoginFailures == nil || *got.LoginFailures != 3 {
		t.Fatalf("expected login failures 3, got %#v", got.LoginFailures)
	}
	if got.LoginSuccesses == nil || *got.LoginSuccesses != 12 {
		t.Fatalf("expected login successes 12, got %#v", got.LoginSuccesses)
	}
}

func TestParseAliasMembershipRIDsRaw(t *testing.T) {
	data := []byte{0x21, 0x02, 0x00, 0x00}

	got := parseAliasMembershipRIDsRaw(data, registry.DWORD)

	if len(got) != 1 || got[0] != 545 {
		t.Fatalf("expected alias rid 545, got %v", got)
	}
}

func TestParseAliasMembershipRIDsRawUTF16StyleData(t *testing.T) {
	data := []byte{0x21, 0x02, 0x00, 0x00, 0x20, 0x02}

	got := parseAliasMembershipRIDsRaw(data, registry.BINARY)

	if len(got) != 2 {
		t.Fatalf("expected two alias rids, got %v", got)
	}
	if !(containsUint32(got, 544) && containsUint32(got, 545)) {
		t.Fatalf("expected alias rids 544 and 545, got %v", got)
	}
}

func putSAMVUTF16Field(data []byte, offsetOffset uint32, lengthOffset uint32, relativeOffset uint32, value string) {
	encoded := encodeUTF16LE(value)
	binary.LittleEndian.PutUint32(data[offsetOffset:offsetOffset+4], relativeOffset)
	binary.LittleEndian.PutUint32(data[lengthOffset:lengthOffset+4], uint32(len(encoded)))
	copy(data[0xCC+relativeOffset:], encoded)
}

func encodeUTF16LE(value string) []byte {
	buf := make([]byte, 0, len(value)*2)
	for _, r := range value {
		code := uint16(r)
		buf = append(buf, byte(code), byte(code>>8))
	}
	return buf
}

func mustFiletimeBytes(rfc3339 string) []byte {
	got, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		panic(err)
	}
	filetime := uint64(got.UnixNano()/100) + 116444736000000000
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, filetime)
	return buf
}

func containsUint32(values []uint32, want uint32) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
