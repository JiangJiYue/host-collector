package hash

const (
	StatePending          = "pending"
	StateSkippedDirectory = "skipped_directory"
	StateSkippedTooLarge  = "skipped_too_large"
)

type Decision struct {
	State      string
	Algorithms []string
}

type Policy struct {
	MaxBytes   int64
	Algorithms []string
}

func DefaultPolicy() Policy {
	return Policy{
		MaxBytes:   32 << 20,
		Algorithms: []string{"md5", "sha1", "sha256"},
	}
}

func (p Policy) Decide(size int64, isDirectory bool) Decision {
	if isDirectory {
		return Decision{State: StateSkippedDirectory}
	}
	if p.MaxBytes > 0 && size > p.MaxBytes {
		return Decision{State: StateSkippedTooLarge}
	}
	algorithms := make([]string, len(p.Algorithms))
	copy(algorithms, p.Algorithms)
	return Decision{State: StatePending, Algorithms: algorithms}
}
