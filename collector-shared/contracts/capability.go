package contracts

type Capability string

const (
	CapabilityProcfsRead           Capability = "procfs_read"
	CapabilityJournaldRead         Capability = "journald_read"
	CapabilitySystemdUnits         Capability = "systemd_units"
	CapabilityAuthLogRead          Capability = "auth_log_read"
	CapabilityUtmpRead             Capability = "utmp_read"
	CapabilityPasswdGroupRead      Capability = "passwd_group_read"
	CapabilitySudoersRead          Capability = "sudoers_read"
	CapabilityCronRead             Capability = "cron_read"
	CapabilityFilesystemStat       Capability = "filesystem_stat"
	CapabilityRootPrivileges       Capability = "root_privileges"
	CapabilityWindowsRegistry      Capability = "registry"
	CapabilityWindowsEventLogs     Capability = "event_log_api"
	CapabilityWindowsWMI           Capability = "wmi"
	CapabilityRawNTFSRead          Capability = "raw_ntfs_read"
	CapabilityModernDesktopUI      Capability = "modern_desktop_ui"
	CapabilityPrefetchWin10Layout  Capability = "prefetch_win10_layout"
	CapabilityProcessHandleDetail  Capability = "process_handle_detail"
	CapabilityWindowsUserArtifacts Capability = "windows_user_artifacts"
	CapabilityBrowserHistorySQLite Capability = "browser_history_sqlite"
)

type CapabilityStatus string

const (
	CapabilityAvailable   CapabilityStatus = "available"
	CapabilityDegraded    CapabilityStatus = "degraded"
	CapabilityUnavailable CapabilityStatus = "unavailable"
)

type SupportLevel string

const (
	SupportModern      SupportLevel = "modern"
	SupportLegacy      SupportLevel = "legacy"
	SupportUnsupported SupportLevel = "unsupported"
)

type CapabilitySet map[Capability]CapabilityStatus

func (set CapabilitySet) Supports(capability Capability) bool {
	switch set[capability] {
	case CapabilityAvailable, CapabilityDegraded:
		return true
	default:
		return false
	}
}

func (set CapabilitySet) Missing(capabilities ...Capability) []Capability {
	var missing []Capability
	for _, capability := range capabilities {
		if !set.Supports(capability) {
			missing = append(missing, capability)
		}
	}
	return missing
}

type CapabilityDetectionResult struct {
	Facts        PlatformFacts `json:"facts"`
	Capabilities CapabilitySet `json:"capabilities"`
	Support      SupportLevel  `json:"support"`
	Reason       string        `json:"reason,omitempty"`
}
