package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"windows-host-collector/models"
)

func TestAttachProcessFileIdentityCopiesEvidenceFields(t *testing.T) {
	collector := NewProcessCollector(false)
	info := &models.ProcessBasicInfo{}
	fileIdentityID := "file-123"
	sha256 := "0123456789abcdef"
	hashState := "completed"
	signatureState := "trusted"
	signerSubject := "CN=Microsoft Windows"
	originalFilename := "svchost.exe"

	collector.attachProcessFileIdentity(info, models.FileIdentity{
		ID:                 fileIdentityID,
		SHA256:             sha256,
		HashState:          hashState,
		SignatureState:     signatureState,
		SignerSubject:      signerSubject,
		PEOriginalFilename: originalFilename,
	})

	if info.FileIdentityID == nil || *info.FileIdentityID != fileIdentityID {
		t.Fatalf("expected file identity id to be copied, got %#v", info.FileIdentityID)
	}
	if info.SHA256 == nil || *info.SHA256 != sha256 {
		t.Fatalf("expected sha256 to be copied, got %#v", info.SHA256)
	}
	if info.HashState == nil || *info.HashState != hashState {
		t.Fatalf("expected hash state to be copied, got %#v", info.HashState)
	}
	if info.SignatureState == nil || *info.SignatureState != signatureState {
		t.Fatalf("expected signature state to be copied, got %#v", info.SignatureState)
	}
	if info.SignerSubject == nil || *info.SignerSubject != signerSubject {
		t.Fatalf("expected signer subject to be copied, got %#v", info.SignerSubject)
	}
	if info.PEOriginalFilename == nil || *info.PEOriginalFilename != originalFilename {
		t.Fatalf("expected original filename to be copied, got %#v", info.PEOriginalFilename)
	}
}

func TestClassifySystemProcessMasqueradePathAnomaly(t *testing.T) {
	signals := classifySystemProcessMasquerade("svchost.exe", `c:\users\public\svchost.exe`, nil, nil)
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %#v", signals)
	}
	if signals[0].Code != "masquerade.path_anomaly" {
		t.Fatalf("expected path anomaly code, got %q", signals[0].Code)
	}
	if signals[0].Severity != "high" {
		t.Fatalf("expected high severity, got %q", signals[0].Severity)
	}
	if signals[0].Message != "系统进程路径异常" {
		t.Fatalf("expected chinese message, got %q", signals[0].Message)
	}
}

func TestClassifySystemProcessMasqueradeExtensionAnomaly(t *testing.T) {
	signals := classifySystemProcessMasquerade("svchost.exe", `c:\windows\system32\svchost.com`, nil, nil)
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %#v", signals)
	}
	if signals[0].Code != "masquerade.extension_anomaly" {
		t.Fatalf("expected extension anomaly code, got %q", signals[0].Code)
	}
}

func TestClassifySystemProcessMasqueradeParentAnomaly(t *testing.T) {
	parent := "explorer.exe"
	signals := classifySystemProcessMasquerade("svchost.exe", `c:\windows\system32\svchost.exe`, &parent, nil)
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %#v", signals)
	}
	if signals[0].Code != "masquerade.parent_anomaly" {
		t.Fatalf("expected parent anomaly code, got %q", signals[0].Code)
	}
}

func TestClassifySystemProcessMasqueradeValidSystemPathHasNoSignals(t *testing.T) {
	parent := "services.exe"
	signals := classifySystemProcessMasquerade("svchost.exe", `c:\windows\system32\svchost.exe`, &parent, nil)
	if len(signals) != 0 {
		t.Fatalf("expected no signals, got %#v", signals)
	}
}

func TestComputeMD5ReturnsHexDigestForExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	got := (&ProcessCollector{}).computeMD5(path)
	if got != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("expected md5 for sample file, got %q", got)
	}
}

func TestComputeMD5ReturnsEmptyForMissingFile(t *testing.T) {
	got := (&ProcessCollector{}).computeMD5(filepath.Join(t.TempDir(), "missing.bin"))
	if got != "" {
		t.Fatalf("expected empty md5 for missing file, got %q", got)
	}
}

func TestFormatHandleFallbackFieldsUseReadableDefaults(t *testing.T) {
	objectType, attributes, typeName := formatHandleFallbackFields(16, 0x2)
	if objectType != "Type-16" {
		t.Fatalf("expected fallback object type, got %q", objectType)
	}
	if attributes != "0x2" {
		t.Fatalf("expected compact hex attributes, got %q", attributes)
	}
	if typeName != "Type-16" {
		t.Fatalf("expected fallback type name, got %q", typeName)
	}
}

func TestShouldResolveHandleNameTargetsNamedWindowsObjects(t *testing.T) {
	if !shouldResolveHandleName("File") {
		t.Fatal("expected File handles to opt into object-name resolution")
	}
	if !shouldResolveHandleName("Mutant") {
		t.Fatal("expected Mutant handles to opt into object-name resolution")
	}
	if shouldResolveHandleName("Thread") {
		t.Fatal("did not expect Thread handles to opt into object-name resolution")
	}
}

func TestProcessDetailProgressStateReportsOnIntervalAndCompletion(t *testing.T) {
	state := newProcessDetailProgressState(25, 10)
	if state.ShouldReport() {
		t.Fatal("did not expect report before any process is handled")
	}

	state.Processed = 10
	if !state.ShouldReport() {
		t.Fatal("expected report at interval boundary")
	}

	state.MarkReported()
	if state.ShouldReport() {
		t.Fatal("did not expect duplicate report without new progress")
	}

	state.Processed = 25
	if !state.ShouldReport() {
		t.Fatal("expected report at completion")
	}
}

func TestProcessCollectorProgressCallbackReceivesPayload(t *testing.T) {
	var got ProcessProgress
	called := false

	collector := NewProcessCollector(true).WithProgress(func(progress ProcessProgress) {
		called = true
		got = progress
	})

	collector.report(ProcessProgress{
		PID:         4321,
		ProcessName: "svchost.exe",
		Processed:   17,
		Total:       249,
	})

	if !called {
		t.Fatal("expected progress callback to be invoked")
	}
	if got.PID != 4321 {
		t.Fatalf("expected PID to be preserved, got %d", got.PID)
	}
	if got.ProcessName != "svchost.exe" {
		t.Fatalf("expected process name to be preserved, got %q", got.ProcessName)
	}
	if got.Processed != 17 || got.Total != 249 {
		t.Fatalf("expected processed/total to be preserved, got %d/%d", got.Processed, got.Total)
	}
}

func TestProcessCollectorWithDetailWorkersClampsToOne(t *testing.T) {
	collector := NewProcessCollector(true).WithDetailWorkers(0)
	if collector.detailWorkerCount() != 1 {
		t.Fatalf("expected non-positive worker count to clamp to 1, got %d", collector.detailWorkerCount())
	}
}

func TestProcessCollectorWithDetailWorkersUsesConfiguredCount(t *testing.T) {
	collector := NewProcessCollector(true).WithDetailWorkers(4)
	if collector.detailWorkerCount() != 4 {
		t.Fatalf("expected configured worker count to be preserved, got %d", collector.detailWorkerCount())
	}
}

func TestCollectProcessDetailWithTimeoutReturnsWhenDetailCollectionBlocks(t *testing.T) {
	collector := NewProcessCollector(true).WithDetailTimeout(10 * time.Millisecond)
	collector.detailCollector = func(context.Context, *models.ProcessBasicInfo) (*models.ProcessDetail, processDetailCounts, error) {
		select {}
	}

	started := time.Now()
	_, _, err := collector.collectProcessDetailWithTimeout(context.Background(), &models.ProcessBasicInfo{
		PID:         5364,
		ProcessName: "HipsTray.exe",
	})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("expected timeout to return promptly, elapsed %s", elapsed)
	}
}

func TestGroupProcessWindowsByPIDKeepsPerProcessWindows(t *testing.T) {
	rows := []enumeratedProcessWindow{
		{
			PID: 101,
			Window: models.ProcessWindow{
				Handle:    "0x1",
				ThreadID:  11,
				ClassName: "Chrome_WidgetWin_1",
				Title:     "Console",
				Rect:      [4]int{1, 2, 3, 4},
				Visible:   true,
			},
		},
		{
			PID: 202,
			Window: models.ProcessWindow{
				Handle:    "0x2",
				ThreadID:  22,
				ClassName: "CabinetWClass",
				Title:     "Explorer",
				Rect:      [4]int{5, 6, 7, 8},
				Visible:   false,
			},
		},
		{
			PID: 101,
			Window: models.ProcessWindow{
				Handle:    "0x3",
				ThreadID:  33,
				ClassName: "Notepad",
				Title:     "notes.txt",
				Rect:      [4]int{9, 10, 11, 12},
				Visible:   true,
			},
		},
	}

	grouped := groupProcessWindowsByPID(rows)
	if len(grouped) != 2 {
		t.Fatalf("expected 2 grouped process entries, got %d", len(grouped))
	}
	if len(grouped[101]) != 2 {
		t.Fatalf("expected pid 101 to keep 2 windows, got %#v", grouped[101])
	}
	if grouped[101][0].Handle != "0x1" || grouped[101][1].Handle != "0x3" {
		t.Fatalf("expected pid 101 window order to be preserved, got %#v", grouped[101])
	}
	if len(grouped[202]) != 1 || grouped[202][0].Handle != "0x2" {
		t.Fatalf("expected pid 202 to keep its single window, got %#v", grouped[202])
	}
}
