package collector

import "testing"

func TestEventLogProgressStatePreservesFullChannelCount(t *testing.T) {
	state := newEventLogProgressState(defaultEventLogLimits(), 50)
	if state.ChannelsTotal != 50 {
		t.Fatalf("expected progress state to preserve full channel count, got %d", state.ChannelsTotal)
	}
}

func TestEventLogProgressReportsPeriodically(t *testing.T) {
	limits := defaultEventLogLimits()
	limits.ProgressEveryChannels = 2
	limits.ProgressEveryEvents = 5

	state := newEventLogProgressState(limits, 8)
	if state.ShouldReportProgress() {
		t.Fatal("did not expect progress before work starts")
	}

	state.ChannelsDone = 2
	if !state.ShouldReportProgress() {
		t.Fatal("expected progress report on channel boundary")
	}

	state.MarkReported()
	state.TotalEvents = 5
	if !state.ShouldReportProgress() {
		t.Fatal("expected progress report on event boundary")
	}
}
