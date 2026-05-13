package scanner

import "runtime"

type ExecutionProfile struct {
	Name                 string
	ProcessDetailWorkers int
	AllowHandleNames     bool
	AllowDeepRegistry    bool
}

func DeriveExecutionProfile() ExecutionProfile {
	return deriveExecutionProfileFor(runtime.NumCPU(), runtime.GOOS)
}

func deriveExecutionProfileFor(cpus int, goos string) ExecutionProfile {
	workers := cpus / 2
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	if goos == "windows" && workers > 2 {
		workers = 2
	}

	return ExecutionProfile{
		Name:                 "adaptive",
		ProcessDetailWorkers: workers,
		AllowHandleNames:     cpus >= 4,
		AllowDeepRegistry:    true,
	}
}
