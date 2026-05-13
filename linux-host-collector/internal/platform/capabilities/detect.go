package capabilities

import (
	"os"
	"path/filepath"

	"collector-shared/contracts"
)

func Detect(root string, goarch string) (contracts.CapabilityDetectionResult, error) {
	facts := readPlatformFacts(root, goarch)
	caps := contracts.CapabilitySet{}
	setByPath(caps, contracts.CapabilityProcfsRead, filepath.Join(root, "proc"))
	setByPath(caps, contracts.CapabilityPasswdGroupRead, filepath.Join(root, "etc", "passwd"))
	setByPath(caps, contracts.CapabilitySystemdUnits, filepath.Join(root, "run", "systemd", "system"))
	setByPath(caps, contracts.CapabilityAuthLogRead, filepath.Join(root, "var", "log", "auth.log"))
	setAnyPath(caps, contracts.CapabilityUtmpRead, []string{
		filepath.Join(root, "var", "log", "wtmp"),
		filepath.Join(root, "var", "log", "btmp"),
		filepath.Join(root, "var", "log", "lastlog"),
	})
	setByPath(caps, contracts.CapabilityFilesystemStat, root)
	if os.Geteuid() == 0 {
		caps[contracts.CapabilityRootPrivileges] = contracts.CapabilityAvailable
	} else {
		caps[contracts.CapabilityRootPrivileges] = contracts.CapabilityUnavailable
	}

	support := contracts.SupportModern
	reason := "capabilities_detected"
	if !caps.Supports(contracts.CapabilityProcfsRead) {
		support = contracts.SupportUnsupported
		reason = "missing_procfs"
	}

	return contracts.CapabilityDetectionResult{
		Facts:        facts,
		Capabilities: caps,
		Support:      support,
		Reason:       reason,
	}, nil
}

func setByPath(caps contracts.CapabilitySet, capability contracts.Capability, path string) {
	if _, err := os.Stat(path); err == nil {
		caps[capability] = contracts.CapabilityAvailable
		return
	}
	caps[capability] = contracts.CapabilityUnavailable
}

func setAnyPath(caps contracts.CapabilitySet, capability contracts.Capability, paths []string) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			caps[capability] = contracts.CapabilityAvailable
			return
		}
	}
	caps[capability] = contracts.CapabilityUnavailable
}
