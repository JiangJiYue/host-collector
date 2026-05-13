package collector

type ProcessProgress struct {
	PID         int
	ProcessName string
	Processed   int
	Total       int
}

type processDetailProgressState struct {
	Processed        int
	Total            int
	ReportEvery      int
	lastReportedStep int
}

func newProcessDetailProgressState(total, reportEvery int) *processDetailProgressState {
	return &processDetailProgressState{
		Total:       total,
		ReportEvery: reportEvery,
	}
}

func (s *processDetailProgressState) ShouldReport() bool {
	if s.Processed <= 0 || s.Processed == s.lastReportedStep {
		return false
	}
	if s.Total > 0 && s.Processed >= s.Total {
		return true
	}
	return s.ReportEvery > 0 && s.Processed%s.ReportEvery == 0
}

func (s *processDetailProgressState) MarkReported() {
	s.lastReportedStep = s.Processed
}
