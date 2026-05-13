package appcore

import (
	"strconv"
	"time"
)

type ScanStatusSummary struct {
	Message  string
	ScanID   string
	ScanType string
	Duration time.Duration
	Written  bool
}

type ScanProgressSummary struct {
	Step      string
	StageKey  string
	StageName string
	State     StatusState
	Current   int
	Total     int
	Detail    string
}

func ScanProgressEvent(summary ScanProgressSummary) StatusEvent {
	return StatusEvent{
		Type:      EventScanProgress,
		StageKey:  summary.StageKey,
		StageName: summary.StageName,
		State:     summary.State,
		Current:   summary.Current,
		Total:     summary.Total,
		Detail:    summary.Detail,
		Attributes: map[string]string{
			"step": summary.Step,
		},
	}
}

func OutputProgressEvent(step string, current int, total int) StatusEvent {
	return StatusEvent{
		Type:      EventOutputProgress,
		StageKey:  "output",
		StageName: "本地输出",
		State:     StateRunning,
		Current:   current,
		Total:     total,
		Attributes: map[string]string{
			"step": step,
		},
	}
}

func ScanFailureEvent(summary ScanStatusSummary) StatusEvent {
	return StatusEvent{
		Type:    EventScanFailed,
		State:   StateFailed,
		Message: summary.Message,
		Attributes: map[string]string{
			"scanId":   summary.ScanID,
			"scanType": summary.ScanType,
		},
	}
}

func ScanCompletionEvent(summary ScanStatusSummary) StatusEvent {
	return StatusEvent{
		Type:    EventScanCompleted,
		State:   StateCompleted,
		Message: summary.Message,
		Attributes: map[string]string{
			"scanId":   summary.ScanID,
			"scanType": summary.ScanType,
			"duration": summary.Duration.String(),
			"written":  strconv.FormatBool(summary.Written),
		},
	}
}
