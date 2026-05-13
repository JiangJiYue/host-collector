//go:build windows

package capabilities

import (
	"errors"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var wevtapi = windows.NewLazySystemDLL("wevtapi.dll")
var procEvtOpenChannelEnum = wevtapi.NewProc("EvtOpenChannelEnum")
var procEvtClose = wevtapi.NewProc("EvtClose")

func DetectWindowsFacts() WindowsFacts {
	facts := WindowsFacts{Architecture: runtime.GOARCH}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return facts
	}
	defer key.Close()

	facts.ProductName, _, _ = key.GetStringValue("ProductName")
	facts.EditionID, _, _ = key.GetStringValue("EditionID")
	facts.InstallationType, _, _ = key.GetStringValue("InstallationType")
	if ubr, _, err := key.GetIntegerValue("UBR"); err == nil {
		facts.UBR = int(ubr)
	}
	if major, _, err := key.GetIntegerValue("CurrentMajorVersionNumber"); err == nil {
		facts.MajorVersion = int(major)
	}
	if minor, _, err := key.GetIntegerValue("CurrentMinorVersionNumber"); err == nil {
		facts.MinorVersion = int(minor)
	}
	if facts.MajorVersion == 0 {
		if version, _, err := key.GetStringValue("CurrentVersion"); err == nil {
			parseCurrentVersion(version, &facts)
		}
	}
	if build, _, err := key.GetStringValue("CurrentBuild"); err == nil {
		facts.BuildNumber = parseLeadingInt(build)
	}
	if facts.BuildNumber == 0 {
		if build, _, err := key.GetStringValue("CurrentBuildNumber"); err == nil {
			facts.BuildNumber = parseLeadingInt(build)
		}
	}
	facts.WebView2Runtime = detectWebView2Runtime()
	facts.FilesystemTypes = detectFilesystemTypes()
	facts.IsElevated = detectIsElevated()
	facts.HasBackupPrivilege = tokenHasPrivilege("SeBackupPrivilege")
	facts.HasSeDebugPrivilege = tokenHasPrivilege("SeDebugPrivilege")
	facts.CapabilityProbes = detectCapabilityProbes(facts)
	return facts
}

func detectCapabilityProbes(facts WindowsFacts) map[Capability]ProbeStatus {
	return detectBaseCapabilityProbes(facts, detectCoreCapabilityProbes())
}

func detectCoreCapabilityProbes() map[Capability]ProbeStatus {
	return map[Capability]ProbeStatus{
		CapabilityWMI:         probeWMI(),
		CapabilityEventLogAPI: probeEventLogAPI(),
		CapabilityRegistry:    probeRegistry(),
	}
}

func probeWMI() ProbeStatus {
	var rows []struct {
		Caption string
	}
	if err := wmi.Query("SELECT Caption FROM Win32_OperatingSystem", &rows); err != nil {
		return ProbeStatus{Supported: false, Reason: "wmi_unavailable", Evidence: compactProbeError(err)}
	}
	return ProbeStatus{Supported: true, Reason: "available", Evidence: "Win32_OperatingSystem"}
}

func probeEventLogAPI() ProbeStatus {
	handle, _, err := procEvtOpenChannelEnum.Call(0, 0)
	if handle == 0 {
		return ProbeStatus{Supported: false, Reason: eventLogProbeReason(err), Evidence: compactProbeError(err)}
	}
	procEvtClose.Call(handle)
	return ProbeStatus{Supported: true, Reason: "available", Evidence: "EvtOpenChannelEnum"}
}

func probeRegistry() ProbeStatus {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ProbeStatus{Supported: false, Reason: registryProbeReason(err), Evidence: compactProbeError(err)}
	}
	key.Close()
	return ProbeStatus{Supported: true, Reason: "available", Evidence: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"}
}

func eventLogProbeReason(err error) string {
	if errno, ok := err.(syscall.Errno); ok {
		if errno == syscall.ERROR_ACCESS_DENIED {
			return "permission_denied"
		}
	}
	return "event_log_api_unavailable"
}

func registryProbeReason(err error) string {
	if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "registry_key_missing"
	}
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
		return "permission_denied"
	}
	return "registry_view_unavailable"
}

func compactProbeError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if value == "" {
		return "unknown_error"
	}
	return strings.ReplaceAll(value, "\n", " ")
}

func detectWebView2Runtime() string {
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		key, err := registry.OpenKey(root, `SOFTWARE\Microsoft\EdgeUpdate\Clients\{F1C0458B-6E5C-4D3C-8DF1-9F6F9F184BD0}`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		version, _, _ := key.GetStringValue("pv")
		key.Close()
		if version != "" {
			return version
		}
	}
	return "not_detected"
}

func detectFilesystemTypes() []string {
	const bufferChars = 512
	buffer := make([]uint16, bufferChars)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buffer)), &buffer[0])
	if err != nil || n == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	for _, drive := range strings.Split(windows.UTF16ToString(buffer), "\x00") {
		drive = strings.TrimSpace(drive)
		if drive == "" {
			continue
		}
		rootPath, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		fsName := make([]uint16, 64)
		if err := windows.GetVolumeInformation(rootPath, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName))); err != nil {
			continue
		}
		name := strings.TrimSpace(windows.UTF16ToString(fsName))
		if name != "" {
			seen[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func detectIsElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func tokenHasPrivilege(name string) bool {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var wanted windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &wanted); err != nil {
		return false
	}

	var needed uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if err == nil || needed == 0 {
		return false
	}
	buffer := make([]byte, needed)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], needed, &needed); err != nil {
		return false
	}

	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Luid.LowPart == wanted.LowPart && privilege.Luid.HighPart == wanted.HighPart {
			return true
		}
	}
	return false
}

func parseCurrentVersion(version string, facts *WindowsFacts) {
	parts := splitVersion(version)
	if len(parts) > 0 {
		facts.MajorVersion = parseLeadingInt(parts[0])
	}
	if len(parts) > 1 {
		facts.MinorVersion = parseLeadingInt(parts[1])
	}
}

func splitVersion(version string) []string {
	parts := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(version); i++ {
		if version[i] == '.' {
			parts = append(parts, version[start:i])
			start = i + 1
		}
	}
	parts = append(parts, version[start:])
	return parts
}

func parseLeadingInt(value string) int {
	result := 0
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			break
		}
		result = result*10 + int(value[i]-'0')
	}
	return result
}
