package appcore

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestRecorderStoresIndependentEventSnapshots(t *testing.T) {
	recorder := NewRecorder()
	event := StatusEvent{
		Type:      EventScanProgress,
		StageKey:  "system",
		StageName: "系统信息",
		State:     StateRunning,
		Current:   1,
		Total:     3,
		Detail:    "running",
		Attributes: map[string]string{
			"supportLevel": "modern",
		},
	}

	recorder.EmitStatus(event)
	event.Attributes["supportLevel"] = "mutated"

	events := recorder.Events()
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Attributes["supportLevel"] != "modern" {
		t.Fatalf("recorder must snapshot attributes, got %#v", events[0].Attributes)
	}

	events[0].Attributes["supportLevel"] = "changed-again"
	if recorder.Events()[0].Attributes["supportLevel"] != "modern" {
		t.Fatalf("Events must return snapshots, got %#v", recorder.Events()[0].Attributes)
	}
}

func TestNopSinkAcceptsStatusEvents(t *testing.T) {
	var sink StatusSink = NopSink{}
	sink.EmitStatus(StatusEvent{Type: EventUploadProgress, StageKey: "upload", State: StateRunning})
}

func TestUploadProgressEventUsesSharedUploadStage(t *testing.T) {
	event := UploadProgressEvent("encrypting", 1, 3)

	if event.Type != EventUploadProgress {
		t.Fatalf("unexpected type: %#v", event)
	}
	if event.StageKey != "upload" || event.StageName != "上传" || event.State != StateRunning {
		t.Fatalf("unexpected upload stage: %#v", event)
	}
	if event.Current != 1 || event.Total != 3 || event.Attributes["step"] != "encrypting" {
		t.Fatalf("unexpected progress fields: %#v", event)
	}
}

func TestScanProgressEventCarriesStageFieldsAndStepAttribute(t *testing.T) {
	event := ScanProgressEvent(ScanProgressSummary{
		Step:      "collecting",
		StageKey:  "network",
		StageName: "网络",
		State:     StateRunning,
		Current:   2,
		Total:     5,
		Detail:    "enumerating",
	})

	if event.Type != EventScanProgress {
		t.Fatalf("unexpected type: %#v", event)
	}
	if event.StageKey != "network" || event.StageName != "网络" || event.State != StateRunning {
		t.Fatalf("unexpected stage fields: %#v", event)
	}
	if event.Current != 2 || event.Total != 5 || event.Detail != "enumerating" {
		t.Fatalf("unexpected progress fields: %#v", event)
	}
	if event.Attributes["step"] != "collecting" {
		t.Fatalf("expected step attribute, got %#v", event.Attributes)
	}
}

func TestScanFailureAndCompletionEventsCarryIdentityAttributes(t *testing.T) {
	failure := ScanFailureEvent(ScanStatusSummary{
		Message:  "failed",
		ScanID:   "scan-1",
		ScanType: "policy",
	})
	if failure.Type != EventScanFailed || failure.State != StateFailed || failure.Message != "failed" {
		t.Fatalf("unexpected failure event: %#v", failure)
	}
	if failure.Attributes["scanId"] != "scan-1" || failure.Attributes["scanType"] != "policy" {
		t.Fatalf("unexpected failure attributes: %#v", failure.Attributes)
	}

	completion := ScanCompletionEvent(ScanStatusSummary{
		Message:  "completed",
		ScanID:   "scan-1",
		ScanType: "policy",
		Duration: 1500 * time.Millisecond,
		Uploaded: true,
	})
	if completion.Type != EventScanCompleted || completion.State != StateCompleted || completion.Message != "completed" {
		t.Fatalf("unexpected completion event: %#v", completion)
	}
	if completion.Attributes["duration"] != (1500*time.Millisecond).String() || completion.Attributes["uploaded"] != strconv.FormatBool(true) {
		t.Fatalf("unexpected completion attributes: %#v", completion.Attributes)
	}
}

func TestRecorderRecordsConcurrentStatusEvents(t *testing.T) {
	const (
		workers         = 8
		eventsPerWorker = 250
	)

	recorder := NewRecorder()
	start := make(chan struct{})
	writersDone := make(chan struct{})

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for seq := 0; seq < eventsPerWorker; seq++ {
				recorder.EmitStatus(StatusEvent{
					Type:     EventScanProgress,
					StageKey: fmt.Sprintf("worker-%d", worker),
					State:    StateRunning,
					Current:  seq,
					Total:    eventsPerWorker,
					Attributes: map[string]string{
						"key": fmt.Sprintf("%d/%d", worker, seq),
					},
				})
			}
		}()
	}

	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		<-start
		for {
			select {
			case <-writersDone:
				return
			default:
				_ = recorder.Events()
			}
		}
	}()

	close(start)
	wg.Wait()
	close(writersDone)
	readers.Wait()

	events := recorder.Events()
	if len(events) != workers*eventsPerWorker {
		t.Fatalf("expected %d events, got %d", workers*eventsPerWorker, len(events))
	}

	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		seen[event.Attributes["key"]] = struct{}{}
	}
	for worker := 0; worker < workers; worker++ {
		for seq := 0; seq < eventsPerWorker; seq++ {
			key := fmt.Sprintf("%d/%d", worker, seq)
			if _, ok := seen[key]; !ok {
				t.Fatalf("missing event %s", key)
			}
		}
	}
}
