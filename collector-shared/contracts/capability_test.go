package contracts

import "testing"

func TestCapabilityConstantsUseStablePlanValues(t *testing.T) {
	cases := map[Capability]string{
		CapabilityProcfsRead:       "procfs_read",
		CapabilityJournaldRead:     "journald_read",
		CapabilitySystemdUnits:     "systemd_units",
		CapabilityAuthLogRead:      "auth_log_read",
		CapabilityUtmpRead:         "utmp_read",
		CapabilityPasswdGroupRead:  "passwd_group_read",
		CapabilitySudoersRead:      "sudoers_read",
		CapabilityCronRead:         "cron_read",
		CapabilityFilesystemStat:   "filesystem_stat",
		CapabilityRootPrivileges:   "root_privileges",
		CapabilityWindowsRegistry:  "registry",
		CapabilityWindowsEventLogs: "event_log_api",
		CapabilityWindowsWMI:       "wmi",
		CapabilityRawNTFSRead:      "raw_ntfs_read",
	}

	for capability, want := range cases {
		if got := string(capability); got != want {
			t.Fatalf("capability value = %q, want %q", got, want)
		}
	}
}

func TestCapabilitySetReportsMissingCapabilities(t *testing.T) {
	set := CapabilitySet{
		CapabilityProcfsRead:      CapabilityAvailable,
		CapabilityJournaldRead:    CapabilityUnavailable,
		CapabilitySystemdUnits:    CapabilityDegraded,
		CapabilityWindowsRegistry: CapabilityUnavailable,
	}

	if !set.Supports(CapabilityProcfsRead) {
		t.Fatalf("expected procfs read support")
	}
	if set.Supports(CapabilityJournaldRead) {
		t.Fatalf("unavailable journald must not be supported")
	}
	missing := set.Missing(CapabilityProcfsRead, CapabilityJournaldRead, CapabilitySystemdUnits)
	if len(missing) != 1 || missing[0] != CapabilityJournaldRead {
		t.Fatalf("unexpected missing capabilities: %#v", missing)
	}
}

func TestCapabilitySetRejectsUnknownStatuses(t *testing.T) {
	set := CapabilitySet{
		CapabilityProcfsRead:   CapabilityStatus(""),
		CapabilityJournaldRead: CapabilityStatus("unexpected"),
		CapabilitySystemdUnits: CapabilityDegraded,
	}

	if set.Supports(CapabilityProcfsRead) {
		t.Fatalf("empty capability status must not be supported")
	}
	if set.Supports(CapabilityJournaldRead) {
		t.Fatalf("unexpected capability status must not be supported")
	}
	missing := set.Missing(CapabilityProcfsRead, CapabilityJournaldRead, CapabilitySystemdUnits)
	if len(missing) != 2 || missing[0] != CapabilityProcfsRead || missing[1] != CapabilityJournaldRead {
		t.Fatalf("unexpected missing capabilities: %#v", missing)
	}
}

func TestDetectionResultKeepsReasonAndPlatformFactsTogether(t *testing.T) {
	result := CapabilityDetectionResult{
		Facts: PlatformFacts{
			Platform:     PlatformLinux,
			Architecture: ArchitectureAMD64,
		},
		Capabilities: CapabilitySet{
			CapabilityProcfsRead: CapabilityAvailable,
		},
		Support: SupportModern,
		Reason:  "capabilities_detected",
	}

	if result.Facts.Platform != PlatformLinux {
		t.Fatalf("expected linux platform")
	}
	if !result.Capabilities.Supports(CapabilityProcfsRead) {
		t.Fatalf("expected procfs capability support")
	}
	if result.Support != SupportModern || result.Reason == "" {
		t.Fatalf("expected support and reason, got %#v", result)
	}
}
