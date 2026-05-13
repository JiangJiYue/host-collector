package linuxutil

func IsPseudoFilesystem(filesystem string) bool {
	switch filesystem {
	case "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs", "fusectl", "hugetlbfs", "mqueue", "proc", "pstore", "securityfs", "sysfs", "tmpfs", "tracefs":
		return true
	default:
		return false
	}
}

func ContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
