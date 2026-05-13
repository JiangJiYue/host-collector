package host

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"collector-shared/contracts"
	"collector-shared/linuxutil"
	"linux-host-collector/internal/platform/capabilities"
)

const linuxCapabilitiesVersion = "linux-capabilities-v1"

type Result struct {
	Sections map[string]any
}

type NetworkAdapter struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	AdapterName     string   `json:"adapterName,omitempty"`
	MACAddress      string   `json:"macAddress,omitempty"`
	IPAddress       string   `json:"ipAddress,omitempty"`
	IPAddresses     []string `json:"ipAddresses,omitempty"`
	DefaultGateways []string `json:"defaultGateways,omitempty"`
	DNSServers      []string `json:"dnsServers,omitempty"`
	PhysicalAdapter bool     `json:"physicalAdapter"`
	NetEnabled      bool     `json:"netEnabled"`
}

type SecurityFramework struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode,omitempty"`
	Source   string   `json:"source,omitempty"`
	RiskTags []string `json:"riskTags,omitempty"`
}

type KernelCommandLine struct {
	Raw        string            `json:"raw,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	RiskTags   []string          `json:"riskTags,omitempty"`
}

type KernelTaint struct {
	Value    int      `json:"value"`
	Flags    []string `json:"flags,omitempty"`
	RiskTags []string `json:"riskTags,omitempty"`
	Source   string   `json:"source,omitempty"`
}

func Collect(root string, goarch string) Result {
	detected, _ := capabilities.Detect(root, goarch)
	securityFrameworks := collectSecurityFrameworks(root)
	kernelCommandLine := collectKernelCommandLine(root)
	kernelTaint := collectKernelTaint(root)
	hostname := readHostname(root)
	networkAdapters := collectNetworkAdapters(root)
	ipAddresses := collectAdapterIPAddresses(networkAdapters)
	resources := collectResources(root)
	hardware := map[string]any{
		"processor":   processorModel(root, string(detected.Facts.Architecture)),
		"memorySize":  formatGB(resources["memoryTotal"]),
		"biosVersion": biosVersion(root),
		"disks":       diskLabels(root),
	}
	return Result{Sections: map[string]any{
		"platformFacts":   platformFactsWithLinuxSecurityContext(detected.Facts, securityFrameworks, kernelCommandLine, kernelTaint),
		"platformProfile": platformProfile(detected, securityFrameworks, kernelCommandLine, kernelTaint),
		"resources":       resources,
		"hardware":        hardware,
		"system": map[string]any{
			"hostname":        hostname,
			"platform":        "linux",
			"osName":          detected.Facts.OSName,
			"osVersion":       linuxOSVersion(detected.Facts.OSName, detected.Facts.OSVersion),
			"architecture":    string(detected.Facts.Architecture),
			"username":        currentUsername(root),
			"kernelVersion":   detected.Facts.Kernel,
			"ipAddresses":     ipAddresses,
			"networkAdapters": networkAdapters,
		},
	}}
}

func platformFactsWithLinuxSecurityContext(facts contracts.PlatformFacts, frameworks []SecurityFramework, kernelCommandLine KernelCommandLine, kernelTaint KernelTaint) contracts.PlatformFacts {
	if len(frameworks) == 0 && kernelCommandLine.Raw == "" && kernelTaint.Value == 0 {
		return facts
	}
	if facts.Extensions.Linux == nil {
		facts.Extensions.Linux = map[string]any{}
	}
	if len(frameworks) > 0 {
		facts.Extensions.Linux["securityFrameworks"] = frameworks
	}
	if kernelCommandLine.Raw != "" {
		facts.Extensions.Linux["kernelCommandLine"] = kernelCommandLine
	}
	if kernelTaint.Value != 0 {
		facts.Extensions.Linux["kernelTaint"] = kernelTaint
	}
	return facts
}

func platformProfile(detected contracts.CapabilityDetectionResult, securityFrameworks []SecurityFramework, kernelCommandLine KernelCommandLine, kernelTaint KernelTaint) map[string]any {
	linuxExtensions := detected.Facts.Extensions.Linux
	capabilities := make([]string, 0, len(detected.Capabilities))
	statuses := make(map[string]any, len(detected.Capabilities))
	capabilityNames := make([]string, 0, len(detected.Capabilities))
	for capability := range detected.Capabilities {
		capabilityNames = append(capabilityNames, string(capability))
	}
	sort.Strings(capabilityNames)
	for _, capability := range capabilityNames {
		status := detected.Capabilities[contracts.Capability(capability)]
		if status == contracts.CapabilityAvailable || status == contracts.CapabilityDegraded {
			capabilities = append(capabilities, capability)
		}
		statuses[capability] = map[string]any{
			"supported": status == contracts.CapabilityAvailable || status == contracts.CapabilityDegraded,
			"reason":    string(status),
			"evidence":  detected.Reason,
		}
	}

	facts := map[string]any{
		"osName":       detected.Facts.OSName,
		"osVersion":    detected.Facts.OSVersion,
		"kernel":       detected.Facts.Kernel,
		"architecture": string(detected.Facts.Architecture),
		"distroId":     stringValue(linuxExtensions["distroId"]),
		"buildFamily":  stringValue(linuxExtensions["buildFamily"]),
	}
	if len(securityFrameworks) > 0 {
		facts["securityFrameworks"] = securityFrameworks
	}
	if kernelCommandLine.Raw != "" {
		facts["kernelCommandLine"] = kernelCommandLine
	}
	if kernelTaint.Value != 0 {
		facts["kernelTaint"] = kernelTaint
	}

	return map[string]any{
		"platform":            string(contracts.PlatformLinux),
		"supportLevel":        string(detected.Support),
		"capabilitiesVersion": linuxCapabilitiesVersion,
		"capabilities":        capabilities,
		"capabilityStatuses":  statuses,
		"buildFamily":         stringValue(linuxExtensions["buildFamily"]),
		"architecture":        string(detected.Facts.Architecture),
		"facts":               facts,
	}
}

func collectKernelTaint(root string) KernelTaint {
	const relPath = "proc/sys/kernel/tainted"
	valueText := readTrimmed(filepath.Join(root, relPath))
	if valueText == "" {
		return KernelTaint{}
	}
	value, err := strconv.Atoi(valueText)
	if err != nil || value == 0 {
		return KernelTaint{}
	}
	flags := kernelTaintFlags(value)
	return KernelTaint{
		Value:    value,
		Flags:    flags,
		RiskTags: kernelTaintRiskTags(flags),
		Source:   relPath,
	}
}

func kernelTaintFlags(value int) []string {
	knownFlags := []struct {
		bit  int
		name string
	}{
		{0, "proprietary_module"},
		{1, "forced_module"},
		{2, "unsafe_smp_processor"},
		{3, "forced_rmmod"},
		{4, "machine_check_exception"},
		{5, "bad_page"},
		{6, "user_taint"},
		{7, "die"},
		{8, "acpi_table_overridden"},
		{9, "kernel_warning"},
		{10, "staging_driver"},
		{11, "firmware_workaround"},
		{12, "out_of_tree_module"},
		{13, "unsigned_module"},
		{14, "soft_lockup"},
		{15, "live_patched"},
		{16, "auxiliary_taint"},
		{17, "randstruct_plugin"},
		{18, "in_kernel_test"},
	}
	var flags []string
	for _, flag := range knownFlags {
		if value&(1<<flag.bit) != 0 {
			flags = append(flags, flag.name)
		}
	}
	return flags
}

func kernelTaintRiskTags(flags []string) []string {
	var tags []string
	if linuxutil.ContainsString(flags, "proprietary_module") {
		tags = append(tags, "kernel_tainted_proprietary_module")
	}
	if linuxutil.ContainsString(flags, "forced_module") {
		tags = append(tags, "kernel_tainted_forced_module")
	}
	if linuxutil.ContainsString(flags, "forced_rmmod") {
		tags = append(tags, "kernel_tainted_forced_rmmod")
	}
	if linuxutil.ContainsString(flags, "out_of_tree_module") {
		tags = append(tags, "kernel_tainted_out_of_tree_module")
	}
	if linuxutil.ContainsString(flags, "unsigned_module") {
		tags = append(tags, "kernel_tainted_unsigned_module")
	}
	return tags
}

func collectKernelCommandLine(root string) KernelCommandLine {
	raw := readTrimmed(filepath.Join(root, "proc", "cmdline"))
	if raw == "" {
		return KernelCommandLine{}
	}
	parameters := parseKernelCommandLine(raw)
	return KernelCommandLine{
		Raw:        raw,
		Parameters: parameters,
		RiskTags:   kernelCommandLineRiskTags(parameters),
	}
}

func parseKernelCommandLine(raw string) map[string]string {
	parameters := map[string]string{}
	for _, field := range strings.Fields(raw) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			parameters[field] = "true"
			continue
		}
		if key == "" {
			continue
		}
		parameters[key] = value
	}
	return parameters
}

func kernelCommandLineRiskTags(parameters map[string]string) []string {
	var tags []string
	if parameters["audit"] == "0" {
		tags = append(tags, "audit_disabled")
	}
	if parameters["selinux"] == "0" {
		tags = append(tags, "selinux_disabled_boot")
	}
	if parameters["apparmor"] == "0" {
		tags = append(tags, "apparmor_disabled_boot")
	}
	if value := parameters["init"]; value != "" && value != "/sbin/init" && value != "/lib/systemd/systemd" && value != "/usr/lib/systemd/systemd" {
		tags = append(tags, "custom_init")
	}
	if parameters["single"] == "true" || parameters["1"] == "true" || parameters["systemd.unit"] == "rescue.target" || parameters["systemd.unit"] == "emergency.target" {
		tags = append(tags, "single_user_boot")
	}
	if parameters["module.sig_enforce"] == "0" {
		tags = append(tags, "module_signature_enforcement_disabled")
	}
	return tags
}

func collectSecurityFrameworks(root string) []SecurityFramework {
	var frameworks []SecurityFramework
	frameworks = append(frameworks, collectSELinuxStatus(root))
	frameworks = append(frameworks, collectAppArmorStatus(root))
	sort.Slice(frameworks, func(i, j int) bool {
		return frameworks[i].Name < frameworks[j].Name
	})
	return frameworks
}

func collectSELinuxStatus(root string) SecurityFramework {
	relPath := filepath.Join("sys", "fs", "selinux", "enforce")
	value := readTrimmed(filepath.Join(root, relPath))
	status := SecurityFramework{Name: "selinux", Source: relPath}
	switch value {
	case "1":
		status.Enabled = true
		status.Mode = "enforcing"
	case "0":
		status.Enabled = true
		status.Mode = "permissive"
		status.RiskTags = []string{"selinux_permissive"}
	default:
		status.Enabled = false
		status.Mode = "disabled"
		status.RiskTags = []string{"selinux_disabled"}
	}
	return status
}

func collectAppArmorStatus(root string) SecurityFramework {
	relPath := filepath.Join("sys", "module", "apparmor", "parameters", "enabled")
	value := strings.ToLower(readTrimmed(filepath.Join(root, relPath)))
	status := SecurityFramework{Name: "apparmor", Source: relPath}
	switch value {
	case "y", "yes", "1", "true":
		status.Enabled = true
		status.Mode = "enforcing"
	default:
		status.Enabled = false
		status.Mode = "disabled"
		status.RiskTags = []string{"apparmor_disabled"}
	}
	return status
}

func readHostname(root string) string {
	for _, path := range []string{
		filepath.Join(root, "proc", "sys", "kernel", "hostname"),
		filepath.Join(root, "etc", "hostname"),
	} {
		hostname := readTrimmed(path)
		if hostname != "" {
			return hostname
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func linuxOSVersion(name string, version string) string {
	if name == "" {
		return version
	}
	if version == "" {
		return name
	}
	return strings.TrimSpace(name + " " + version)
}

func currentUsername(root string) string {
	passwd := filepath.Join(root, "etc", "passwd")
	data, err := os.ReadFile(passwd)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[2] == "0" {
			return parts[0]
		}
	}
	return ""
}

func collectNetworkAdapters(root string) []NetworkAdapter {
	adaptersByName := map[string]*NetworkAdapter{}
	defaultGateways := collectDefaultGateways(root)
	dnsServers := collectDNSServers(root)
	for _, adapter := range collectLiveNetworkAdapters(root, defaultGateways, dnsServers) {
		adapterCopy := adapter
		adaptersByName[adapter.Name] = &adapterCopy
	}
	for _, entry := range collectSysfsAdapters(root) {
		adapter := adaptersByName[entry.Name]
		if adapter == nil {
			adapter = &NetworkAdapter{
				ID:              entry.Name,
				Name:            entry.Name,
				AdapterName:     entry.Name,
				MACAddress:      entry.MACAddress,
				DefaultGateways: defaultGateways[entry.Name],
				DNSServers:      dnsServers,
				PhysicalAdapter: entry.PhysicalAdapter,
				NetEnabled:      entry.NetEnabled,
			}
			adaptersByName[entry.Name] = adapter
		}
	}
	for _, entry := range collectProcNetAddresses(root) {
		adapter := adaptersByName[entry.name]
		if adapter == nil {
			adapter = &NetworkAdapter{
				ID:              entry.name,
				Name:            entry.name,
				AdapterName:     entry.name,
				DefaultGateways: defaultGateways[entry.name],
				DNSServers:      dnsServers,
				PhysicalAdapter: entry.name != "lo",
				NetEnabled:      true,
			}
			adaptersByName[entry.name] = adapter
		}
		if entry.ip != "" && !linuxutil.ContainsString(adapter.IPAddresses, entry.ip) {
			adapter.IPAddresses = append(adapter.IPAddresses, entry.ip)
		}
	}
	names := make([]string, 0, len(adaptersByName))
	for name := range adaptersByName {
		names = append(names, name)
	}
	sort.Strings(names)
	adapters := make([]NetworkAdapter, 0, len(names))
	for _, name := range names {
		adapter := *adaptersByName[name]
		sort.Strings(adapter.IPAddresses)
		if len(adapter.IPAddresses) > 0 {
			adapter.IPAddress = adapter.IPAddresses[0]
		}
		adapters = append(adapters, adapter)
	}
	return adapters
}

func collectLiveNetworkAdapters(root string, defaultGateways map[string][]string, dnsServers []string) []NetworkAdapter {
	if filepath.Clean(root) != string(filepath.Separator) {
		return nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var adapters []NetworkAdapter
	for _, iface := range interfaces {
		ipAddresses := liveInterfaceIPAddresses(iface)
		sort.Strings(ipAddresses)
		adapter := NetworkAdapter{
			ID:              iface.Name,
			Name:            iface.Name,
			AdapterName:     iface.Name,
			MACAddress:      iface.HardwareAddr.String(),
			IPAddresses:     ipAddresses,
			DefaultGateways: defaultGateways[iface.Name],
			DNSServers:      dnsServers,
			PhysicalAdapter: iface.Name != "lo" && len(iface.HardwareAddr) > 0,
			NetEnabled:      iface.Flags&net.FlagUp != 0,
		}
		if len(adapter.IPAddresses) > 0 {
			adapter.IPAddress = adapter.IPAddresses[0]
		}
		adapters = append(adapters, adapter)
	}
	return adapters
}

func liveInterfaceIPAddresses(iface net.Interface) []string {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var ipAddresses []string
	for _, addr := range addrs {
		value := addr.String()
		ipValue, _, _ := strings.Cut(value, "/")
		ip := net.ParseIP(ipValue)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		normalized := ip.String()
		if !linuxutil.ContainsString(ipAddresses, normalized) {
			ipAddresses = append(ipAddresses, normalized)
		}
	}
	return ipAddresses
}

type sysfsAdapter struct {
	Name            string
	MACAddress      string
	PhysicalAdapter bool
	NetEnabled      bool
}

func collectSysfsAdapters(root string) []sysfsAdapter {
	netRoot := filepath.Join(root, "sys", "class", "net")
	entries, err := os.ReadDir(netRoot)
	if err != nil {
		return nil
	}
	var adapters []sysfsAdapter
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		adapterRoot := filepath.Join(netRoot, name)
		operstate := readTrimmed(filepath.Join(adapterRoot, "operstate"))
		adapterType := readTrimmed(filepath.Join(adapterRoot, "type"))
		adapters = append(adapters, sysfsAdapter{
			Name:            name,
			MACAddress:      readTrimmed(filepath.Join(adapterRoot, "address")),
			PhysicalAdapter: name != "lo" && adapterType == "1",
			NetEnabled:      operstate == "up" || operstate == "unknown",
		})
	}
	return adapters
}

func collectDefaultGateways(root string) map[string][]string {
	gateways := map[string][]string{}
	data, err := os.ReadFile(filepath.Join(root, "proc", "net", "route"))
	if err != nil {
		return gateways
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "Iface" || fields[1] != "00000000" {
			continue
		}
		gateway := decodeProcIPv4(fields[2])
		if gateway == "" || gateway == "0.0.0.0" {
			continue
		}
		if !linuxutil.ContainsString(gateways[fields[0]], gateway) {
			gateways[fields[0]] = append(gateways[fields[0]], gateway)
		}
	}
	return gateways
}

func collectDNSServers(root string) []string {
	data, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && !linuxutil.ContainsString(servers, fields[1]) {
			servers = append(servers, fields[1])
		}
	}
	return servers
}

func collectAdapterIPAddresses(adapters []NetworkAdapter) []string {
	var addresses []string
	for _, adapter := range adapters {
		for _, ip := range adapter.IPAddresses {
			if ip != "" && !linuxutil.ContainsString(addresses, ip) {
				addresses = append(addresses, ip)
			}
		}
	}
	return addresses
}

type procNetAddress struct {
	name string
	ip   string
}

func collectProcNetAddresses(root string) []procNetAddress {
	var addresses []procNetAddress
	for _, source := range []string{
		filepath.Join(root, "proc", "net", "tcp"),
		filepath.Join(root, "proc", "net", "udp"),
	} {
		data, err := os.ReadFile(source)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] == "sl" {
				continue
			}
			endpoint := fields[1]
			ipHex, _, ok := strings.Cut(endpoint, ":")
			if !ok {
				continue
			}
			ip := decodeProcIPv4(ipHex)
			if ip == "" || ip == "0.0.0.0" {
				continue
			}
			name := "eth0"
			if strings.HasPrefix(ip, "127.") {
				name = "lo"
			}
			addresses = append(addresses, procNetAddress{name: name, ip: ip})
		}
	}
	return addresses
}

func decodeProcIPv4(value string) string {
	if len(value) != 8 {
		return ""
	}
	bytes := make([]string, 0, 4)
	for i := 6; i >= 0; i -= 2 {
		part := value[i : i+2]
		n, ok := parseHexByte(part)
		if !ok {
			return ""
		}
		bytes = append(bytes, n)
	}
	return strings.Join(bytes, ".")
}

func parseHexByte(value string) (string, bool) {
	number, err := strconv.ParseUint(value, 16, 8)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(number, 10), true
}

func collectResources(root string) map[string]any {
	totalGB, usedGB, usagePercent := memoryStatsGB(filepath.Join(root, "proc", "meminfo"))
	return map[string]any{
		"cpuUsage":    cpuUsagePercent(filepath.Join(root, "proc", "stat")),
		"memoryUsage": usagePercent,
		"memoryUsed":  usedGB,
		"memoryTotal": totalGB,
		"disks":       diskUsageRows(root),
	}
}

func cpuUsagePercent(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var total uint64
		var idle uint64
		for index, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				continue
			}
			total += value
			if index == 3 || index == 4 {
				idle += value
			}
		}
		if total == 0 {
			return 0
		}
		busy := total - idle
		return float64(busy) / float64(total) * 100
	}
	return 0
}

func memoryStatsGB(path string) (float64, float64, float64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0
	}
	values := map[string]float64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		kb, err := strconv.ParseFloat(fields[1], 64)
		if err == nil {
			values[key] = kb
		}
	}
	totalKB := values["MemTotal"]
	availableKB := values["MemAvailable"]
	if availableKB == 0 {
		availableKB = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	usedKB := totalKB - availableKB
	if usedKB < 0 {
		usedKB = 0
	}
	usagePercent := 0.0
	if totalKB > 0 {
		usagePercent = usedKB / totalKB * 100
	}
	return totalKB / 1024 / 1024, usedKB / 1024 / 1024, usagePercent
}

func processorModel(root string, fallback string) string {
	data, err := os.ReadFile(filepath.Join(root, "proc", "cpuinfo"))
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "model name" {
			model := strings.TrimSpace(value)
			if model != "" {
				return model
			}
		}
	}
	return fallback
}

func biosVersion(root string) string {
	for _, path := range []string{
		filepath.Join(root, "sys", "class", "dmi", "id", "bios_version"),
		filepath.Join(root, "sys", "class", "dmi", "id", "product_version"),
		filepath.Join(root, "sys", "class", "dmi", "id", "board_version"),
	} {
		if value := readTrimmed(path); value != "" {
			return value
		}
	}
	return ""
}

func diskLabels(root string) []string {
	disks := physicalDiskSummaries(root)
	labels := make([]string, 0, len(disks))
	for _, disk := range disks {
		labels = append(labels, disk.Name)
	}
	if len(labels) == 0 {
		return []string{"/"}
	}
	return labels
}

func diskUsageRows(root string) []map[string]any {
	disks := physicalDiskSummaries(root)
	rows := make([]map[string]any, 0, len(disks))
	for _, disk := range disks {
		mountRows := make([]map[string]any, 0, len(disk.Mounts))
		var total, used float64
		var usageSource string
		for _, mount := range disk.Mounts {
			mountTotal, mountUsed, mountUsage := statMountUsage(root, mount.mountPoint)
			if mount.mountPoint == "/" || total == 0 {
				total, used = mountTotal, mountUsed
				usageSource = mount.mountPoint
			}
			mountRows = append(mountRows, map[string]any{
				"drive":      mount.mountPoint,
				"device":     mount.device,
				"filesystem": mount.fsType,
				"usage":      mountUsage,
				"used":       mountUsed,
				"total":      mountTotal,
			})
		}
		if total == 0 && disk.SizeBytes > 0 {
			total = float64(disk.SizeBytes) / 1024 / 1024 / 1024
		}
		usage := 0.0
		if total > 0 {
			usage = used / total * 100
		}
		rows = append(rows, map[string]any{
			"name":        disk.Name,
			"drive":       usageSource,
			"device":      disk.DevicePath,
			"filesystem":  primaryFilesystem(disk.Mounts),
			"usage":       usage,
			"used":        used,
			"total":       total,
			"mounts":      mountRows,
			"mountPoints": mountPoints(disk.Mounts),
		})
	}
	if len(rows) == 0 {
		total, used, usage := statMountUsage(root, "/")
		rows = append(rows, map[string]any{
			"drive": "/",
			"usage": usage,
			"used":  used,
			"total": total,
		})
	}
	return rows
}

type mountEntry struct {
	device     string
	mountPoint string
	fsType     string
}

type diskSummary struct {
	Name       string
	DevicePath string
	SizeBytes  uint64
	Mounts     []mountEntry
}

func physicalDiskSummaries(root string) []diskSummary {
	mounts := readMounts(root)
	rootDisk := ""
	for _, mount := range mounts {
		if mount.mountPoint == "/" {
			rootDisk = diskNameForDevice(mount.device)
			break
		}
	}
	byDisk := map[string]*diskSummary{}
	for _, mount := range mounts {
		if !shouldShowDiskMount(mount) {
			continue
		}
		diskName := diskNameForDevice(mount.device)
		if diskName == "" && mount.fsType == "efivarfs" {
			diskName = rootDisk
		}
		if diskName == "" {
			continue
		}
		summary := byDisk[diskName]
		if summary == nil {
			summary = &diskSummary{
				Name:       diskName,
				DevicePath: "/dev/" + diskName,
				SizeBytes:  blockDeviceSizeBytes(root, diskName),
			}
			byDisk[diskName] = summary
		}
		if !mountPointExists(summary.Mounts, mount.mountPoint) {
			summary.Mounts = append(summary.Mounts, mount)
		}
	}
	names := make([]string, 0, len(byDisk))
	for name := range byDisk {
		names = append(names, name)
	}
	sort.Strings(names)
	disks := make([]diskSummary, 0, len(names))
	for _, name := range names {
		summary := *byDisk[name]
		sort.Slice(summary.Mounts, func(i, j int) bool {
			left := mountSortRank(summary.Mounts[i].mountPoint)
			right := mountSortRank(summary.Mounts[j].mountPoint)
			if left == right {
				return summary.Mounts[i].mountPoint < summary.Mounts[j].mountPoint
			}
			return left < right
		})
		disks = append(disks, summary)
	}
	return disks
}

func shouldShowDiskMount(mount mountEntry) bool {
	if mount.mountPoint == "" || strings.HasPrefix(mount.device, "/dev/loop") {
		return false
	}
	if linuxutil.IsPseudoFilesystem(mount.fsType) || strings.HasPrefix(mount.fsType, "fuse.") || mount.fsType == "squashfs" || mount.fsType == "nsfs" {
		return false
	}
	if mount.mountPoint == "/" || mount.mountPoint == "/boot/efi" || mount.mountPoint == "/sys/firmware/efi/efivars" {
		return true
	}
	return isPhysicalBlockDevice(mount.device)
}

func diskNameForDevice(device string) string {
	if !isPhysicalBlockDevice(device) {
		return ""
	}
	name := strings.TrimPrefix(device, "/dev/")
	if strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk") {
		if index := strings.LastIndex(name, "p"); index > 0 {
			return name[:index]
		}
	}
	for len(name) > 0 {
		last := name[len(name)-1]
		if last < '0' || last > '9' {
			break
		}
		name = name[:len(name)-1]
	}
	return name
}

func isPhysicalBlockDevice(device string) bool {
	name := strings.TrimPrefix(device, "/dev/")
	return strings.HasPrefix(name, "sd") ||
		strings.HasPrefix(name, "vd") ||
		strings.HasPrefix(name, "xvd") ||
		strings.HasPrefix(name, "hd") ||
		strings.HasPrefix(name, "nvme") ||
		strings.HasPrefix(name, "mmcblk")
}

func blockDeviceSizeBytes(root string, diskName string) uint64 {
	sectors := parseTrimmedUint(filepath.Join(root, "sys", "block", diskName, "size"))
	blockSize := parseTrimmedUint(filepath.Join(root, "sys", "block", diskName, "queue", "logical_block_size"))
	if blockSize == 0 {
		blockSize = 512
	}
	return sectors * blockSize
}

func parseTrimmedUint(path string) uint64 {
	parsed, err := strconv.ParseUint(readTrimmed(path), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func mountPointExists(mounts []mountEntry, mountPoint string) bool {
	for _, mount := range mounts {
		if mount.mountPoint == mountPoint {
			return true
		}
	}
	return false
}

func mountSortRank(mountPoint string) string {
	switch mountPoint {
	case "/":
		return "0"
	case "/sys/firmware/efi/efivars":
		return "1"
	case "/boot/efi":
		return "2"
	default:
		return "9" + mountPoint
	}
}

func primaryFilesystem(mounts []mountEntry) string {
	for _, mount := range mounts {
		if mount.mountPoint == "/" {
			return mount.fsType
		}
	}
	if len(mounts) > 0 {
		return mounts[0].fsType
	}
	return ""
}

func mountPoints(mounts []mountEntry) []string {
	points := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		points = append(points, mount.mountPoint)
	}
	return points
}

func readMounts(root string) []mountEntry {
	data, err := os.ReadFile(filepath.Join(root, "proc", "mounts"))
	if err != nil {
		return nil
	}
	var mounts []mountEntry
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mounts = append(mounts, mountEntry{
			device:     unescapeMountField(fields[0]),
			mountPoint: unescapeMountField(fields[1]),
			fsType:     fields[2],
		})
	}
	return mounts
}

func statMountUsage(root string, mountPoint string) (float64, float64, float64) {
	path := root
	cleanMount := filepath.Clean(mountPoint)
	if cleanMount != string(filepath.Separator) {
		path = filepath.Join(root, strings.TrimPrefix(cleanMount, string(filepath.Separator)))
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}
	total := float64(stat.Blocks*uint64(stat.Bsize)) / 1024 / 1024 / 1024
	available := float64(stat.Bavail*uint64(stat.Bsize)) / 1024 / 1024 / 1024
	used := total - available
	if used < 0 {
		used = 0
	}
	usage := 0.0
	if total > 0 {
		usage = used / total * 100
	}
	return total, used, usage
}

func unescapeMountField(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func formatGB(value any) string {
	number, ok := value.(float64)
	if !ok || number == 0 {
		return "0 GB"
	}
	return fmt.Sprintf("%.1f GB", number)
}
