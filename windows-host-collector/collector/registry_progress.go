package collector

type RegistryProgress struct {
	RootName   string
	RootsDone  int
	RootsTotal int
	ValuesRead int
}

type registryProgressState struct {
	RootName          string
	RootsDone         int
	RootsTotal        int
	ValuesRead        int
	ReportEveryValues int
	lastReportedValue int
}

func newRegistryProgressState(rootName string, rootsDone, rootsTotal, reportEveryValues int) *registryProgressState {
	return &registryProgressState{
		RootName:          rootName,
		RootsDone:         rootsDone,
		RootsTotal:        rootsTotal,
		ReportEveryValues: reportEveryValues,
	}
}

func (s *registryProgressState) ShouldReport() bool {
	return s.ReportEveryValues > 0 &&
		s.ValuesRead > 0 &&
		s.ValuesRead%s.ReportEveryValues == 0 &&
		s.ValuesRead != s.lastReportedValue
}

func (s *registryProgressState) MarkReported() {
	s.lastReportedValue = s.ValuesRead
}
