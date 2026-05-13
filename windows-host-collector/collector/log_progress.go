package collector

type eventLogLimits struct {
	ProgressEveryChannels int
	ProgressEveryEvents   int
}

type eventLogProgressState struct {
	limits               eventLogLimits
	ChannelsTotal        int
	ChannelsDone         int
	ChannelEvents        int
	TotalEvents          int
	lastReportedChannels int
	lastReportedEvents   int
}

func defaultEventLogLimits() eventLogLimits {
	return eventLogLimits{
		ProgressEveryChannels: 1,
		ProgressEveryEvents:   100,
	}
}

func newEventLogProgressState(limits eventLogLimits, channelsTotal int) *eventLogProgressState {
	return &eventLogProgressState{limits: limits, ChannelsTotal: channelsTotal}
}

func (s *eventLogProgressState) ShouldReportProgress() bool {
	channelTick := s.limits.ProgressEveryChannels > 0 &&
		s.ChannelsDone > 0 &&
		s.ChannelsDone%s.limits.ProgressEveryChannels == 0 &&
		s.ChannelsDone != s.lastReportedChannels

	eventTick := s.limits.ProgressEveryEvents > 0 &&
		s.TotalEvents > 0 &&
		s.TotalEvents%s.limits.ProgressEveryEvents == 0 &&
		s.TotalEvents != s.lastReportedEvents

	return channelTick || eventTick
}

func (s *eventLogProgressState) RecordFetchedEvent() {
	s.ChannelEvents++
	s.TotalEvents++
}

func (s *eventLogProgressState) MarkReported() {
	s.lastReportedChannels = s.ChannelsDone
	s.lastReportedEvents = s.TotalEvents
}
