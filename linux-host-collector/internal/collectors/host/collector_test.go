package host

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestCollectHostSectionsFromFixture(t *testing.T) {
	result := Collect(filepath.Join("..", "testdata", "root"), "amd64")
	if result.Sections["platformFacts"] == nil {
		t.Fatalf("expected platformFacts section")
	}
	platformProfile, ok := result.Sections["platformProfile"].(map[string]any)
	if !ok {
		t.Fatalf("expected linux platformProfile section, got %#v", result.Sections["platformProfile"])
	}
	if platformProfile["platform"] != "linux" {
		t.Fatalf("expected linux platform profile, got %#v", platformProfile)
	}
	if platformProfile["capabilitiesVersion"] != "linux-capabilities-v1" {
		t.Fatalf("expected linux capability version, got %#v", platformProfile)
	}
	if platformProfile["buildFamily"] != "ubuntu" {
		t.Fatalf("expected ubuntu build family, got %#v", platformProfile)
	}
	facts, ok := platformProfile["facts"].(map[string]any)
	if !ok {
		t.Fatalf("expected platform profile facts, got %#v", platformProfile["facts"])
	}
	securityFrameworks, ok := facts["securityFrameworks"].([]SecurityFramework)
	if !ok || len(securityFrameworks) != 2 {
		t.Fatalf("expected linux security framework facts, got %#v", facts["securityFrameworks"])
	}
	selinux := findSecurityFramework(securityFrameworks, "selinux")
	if selinux == nil || selinux.Mode != "permissive" || !testContains(selinux.RiskTags, "selinux_permissive") {
		t.Fatalf("expected permissive SELinux status with risk tag, got %#v", selinux)
	}
	apparmor := findSecurityFramework(securityFrameworks, "apparmor")
	if apparmor == nil || apparmor.Enabled != true || apparmor.Mode != "enforcing" {
		t.Fatalf("expected enabled AppArmor status, got %#v", apparmor)
	}
	kernelCmdline, ok := facts["kernelCommandLine"].(KernelCommandLine)
	if !ok {
		t.Fatalf("expected kernel command line facts, got %#v", facts["kernelCommandLine"])
	}
	if kernelCmdline.Raw == "" || kernelCmdline.Parameters["audit"] != "0" || kernelCmdline.Parameters["init"] != "/bin/bash" {
		t.Fatalf("expected parsed kernel command line parameters, got %#v", kernelCmdline)
	}
	for _, riskTag := range []string{"audit_disabled", "selinux_disabled_boot", "apparmor_disabled_boot", "custom_init"} {
		if !testContains(kernelCmdline.RiskTags, riskTag) {
			t.Fatalf("expected kernel command line risk tag %s, got %#v", riskTag, kernelCmdline.RiskTags)
		}
	}
	kernelTaint, ok := facts["kernelTaint"].(KernelTaint)
	if !ok {
		t.Fatalf("expected kernel taint facts, got %#v", facts["kernelTaint"])
	}
	if kernelTaint.Value != 12289 || !testContains(kernelTaint.Flags, "proprietary_module") || !testContains(kernelTaint.Flags, "out_of_tree_module") || !testContains(kernelTaint.Flags, "unsigned_module") {
		t.Fatalf("expected parsed kernel taint flags, got %#v", kernelTaint)
	}
	if !testContains(kernelTaint.RiskTags, "kernel_tainted_unsigned_module") {
		t.Fatalf("expected unsigned module kernel taint risk, got %#v", kernelTaint.RiskTags)
	}
	system, ok := result.Sections["system"].(map[string]any)
	if !ok {
		t.Fatalf("expected system section")
	}
	if system["platform"] != "linux" {
		t.Fatalf("expected linux platform in system section, got %#v", system)
	}
	if system["osName"] == "" || system["osVersion"] == "" {
		t.Fatalf("expected os identity in system section, got %#v", system)
	}
	if system["architecture"] != "amd64" {
		t.Fatalf("expected normalized architecture in system section, got %#v", system)
	}
	if system["kernelVersion"] == "" {
		t.Fatalf("expected kernelVersion in system section, got %#v", system)
	}
	if system["username"] == "" {
		t.Fatalf("expected username in system section, got %#v", system)
	}
	ipAddresses, ok := system["ipAddresses"].([]string)
	if !ok || len(ipAddresses) == 0 {
		t.Fatalf("expected top-level linux ipAddresses in system section, got %#v", system["ipAddresses"])
	}
	adapters, ok := system["networkAdapters"].([]NetworkAdapter)
	if !ok || len(adapters) == 0 {
		t.Fatalf("expected linux network adapters in system section, got %#v", system["networkAdapters"])
	}
	var eth0 *NetworkAdapter
	var loopback *NetworkAdapter
	for i := range adapters {
		switch adapters[i].Name {
		case "eth0":
			eth0 = &adapters[i]
		case "lo":
			loopback = &adapters[i]
		}
	}
	if eth0 == nil {
		t.Fatalf("expected eth0 adapter from fixture, got %#v", adapters)
	}
	if eth0.MACAddress != "02:42:0a:00:00:02" {
		t.Fatalf("expected eth0 MAC address from sysfs, got %#v", eth0)
	}
	if len(eth0.DefaultGateways) != 1 || eth0.DefaultGateways[0] != "10.0.0.1" {
		t.Fatalf("expected eth0 default gateway from proc route, got %#v", eth0)
	}
	if len(eth0.DNSServers) != 2 {
		t.Fatalf("expected DNS servers from resolv.conf, got %#v", eth0)
	}
	if loopback == nil || len(loopback.IPAddresses) == 0 {
		t.Fatalf("expected loopback adapter from fixture, got %#v", adapters)
	}
	if loopback.PhysicalAdapter {
		t.Fatalf("expected loopback to be marked non-physical, got %#v", loopback)
	}
	encoded, err := json.Marshal(loopback)
	if err != nil {
		t.Fatalf("marshal loopback: %v", err)
	}
	if !jsonContains(string(encoded), `"physicalAdapter":false`) {
		t.Fatalf("expected physicalAdapter=false to be preserved in JSON, got %s", encoded)
	}
	resources, ok := result.Sections["resources"].(map[string]any)
	if !ok {
		t.Fatalf("expected resources section")
	}
	if resources["memoryTotal"].(float64) <= 0 {
		t.Fatalf("expected memory total from meminfo, got %#v", resources)
	}
	if resources["memoryUsed"].(float64) <= 0 || resources["memoryUsage"].(float64) <= 0 {
		t.Fatalf("expected derived memory usage from meminfo, got %#v", resources)
	}
	if resources["cpuUsage"].(float64) <= 0 {
		t.Fatalf("expected CPU usage from proc stat fixture, got %#v", resources)
	}
	disks, ok := resources["disks"].([]map[string]any)
	if !ok || len(disks) != 1 || disks[0]["name"] != "sda" || disks[0]["total"].(float64) <= 0 {
		t.Fatalf("expected disk usage rows, got %#v", resources["disks"])
	}
	if disks[0]["filesystem"] != "ext4" || disks[0]["device"] != "/dev/sda" {
		t.Fatalf("expected physical disk filesystem and device in resource summary, got %#v", disks[0])
	}
	mountRows, ok := disks[0]["mounts"].([]map[string]any)
	if !ok || len(mountRows) != 3 {
		t.Fatalf("expected root disk critical mounts only, got %#v", disks[0]["mounts"])
	}
	for _, mount := range mountRows {
		if mount["device"] == "/dev/loop0" || mount["drive"] == "/snap/bare/5" || mount["drive"] == "/run/user/1000/gvfs" {
			t.Fatalf("expected snap/fuse mounts to be hidden from disk summary, got %#v", mountRows)
		}
	}
	hardware, ok := result.Sections["hardware"].(map[string]any)
	if !ok {
		t.Fatalf("expected hardware section")
	}
	if hardware["processor"] != "Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz" {
		t.Fatalf("expected processor model from cpuinfo, got %#v", hardware)
	}
	if hardware["memorySize"] != "8.0 GB" {
		t.Fatalf("expected memory size from meminfo, got %#v", hardware)
	}
	if hardware["biosVersion"] != "1.2.3" {
		t.Fatalf("expected BIOS version from dmi fixture, got %#v", hardware)
	}
	hardwareDisks, ok := hardware["disks"].([]string)
	if !ok || len(hardwareDisks) != 1 || hardwareDisks[0] != "sda" {
		t.Fatalf("expected disk labels from mounts, got %#v", hardware["disks"])
	}
}

func jsonContains(value string, target string) bool {
	for start := 0; start+len(target) <= len(value); start++ {
		if value[start:start+len(target)] == target {
			return true
		}
	}
	return false
}

func findSecurityFramework(frameworks []SecurityFramework, name string) *SecurityFramework {
	for i := range frameworks {
		if frameworks[i].Name == name {
			return &frameworks[i]
		}
	}
	return nil
}

func testContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
