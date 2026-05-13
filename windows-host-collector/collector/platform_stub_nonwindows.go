//go:build !windows

package collector

import (
	"context"
	"runtime"
	"windows-host-collector/models"

	"github.com/shirou/gopsutil/v3/process"
)

type ServiceCollector struct{}

func NewServiceCollector() *ServiceCollector {
	return &ServiceCollector{}
}

func (sc *ServiceCollector) Name() string {
	return "service"
}

type ServiceCollectionResult struct {
	Services []models.ServiceItem `json:"services"`
	Drivers  []models.DriverItem  `json:"drivers"`
	Startups []models.StartupItem `json:"startups"`
}

func (sc *ServiceCollector) Collect(ctx context.Context) (interface{}, error) {
	return &ServiceCollectionResult{
		Services: []models.ServiceItem{},
		Drivers:  []models.DriverItem{},
		Startups: []models.StartupItem{},
	}, nil
}

func (bhc *BrowserHistoryCollector) collectBrowserHistory(ctx context.Context) []models.BrowserHistoryEntry {
	return []models.BrowserHistoryEntry{}
}

func (lc *LogCollector) collectPlatformLogs(ctx context.Context) []models.WindowsLogItem {
	return []models.WindowsLogItem{}
}

func (nc *NetworkCollector) collectWindowsDNSCache(ctx context.Context) ([]models.DnsCacheRecord, error) {
	return []models.DnsCacheRecord{}, nil
}

func collectNetworkSharesPlatform(ctx context.Context, nc *NetworkCollector) ([]models.NetworkShare, error) {
	return []models.NetworkShare{}, nil
}

func collectHostsEntriesPlatform(ctx context.Context, nc *NetworkCollector) ([]models.HostsEntry, error) {
	return []models.HostsEntry{}, nil
}

func (pc *PrefetchCollector) collectPrefetchEntries() []models.PrefetchEntry {
	return []models.PrefetchEntry{}
}

func (rc *RegistryCollector) collectAllRoots(ctx context.Context) []models.RegistryValue {
	return []models.RegistryValue{}
}

func collectProcessThreads(pid int32) ([]models.ProcessThread, error) {
	return []models.ProcessThread{}, nil
}

func collectProcessModules(pid int32) ([]models.ProcessModule, error) {
	return []models.ProcessModule{}, nil
}

func collectProcessWindows(pid int32) ([]models.ProcessWindow, error) {
	return []models.ProcessWindow{}, nil
}

func snapshotProcessWindows() (map[int32][]models.ProcessWindow, error) {
	return map[int32][]models.ProcessWindow{}, nil
}

func collectProcessHandles(pid int32) ([]models.ProcessHandle, error) {
	return []models.ProcessHandle{}, nil
}

func getProcessHandleCount(p *process.Process) *int {
	return nil
}

func getProcessBaseAddress(p *process.Process) *string {
	return nil
}

func (sc *SoftwareCollector) collectPlatformSoftware(ctx context.Context) ([]models.InstalledSoftwareItem, error) {
	return []models.InstalledSoftwareItem{}, nil
}

func (uc *UsbCollector) collectUsbRecords() []models.UsbRecord {
	return []models.UsbRecord{}
}

func (uc *UserCollector) collectPlatformUsers(ctx context.Context) ([]models.LocalUserAccount, error) {
	// Windows local account collection is unsupported on non-Windows builds.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []models.LocalUserAccount{}, nil
}

func (sc *SystemCollector) collectPlatformNetworkAdapters() ([]models.NetworkAdapterInfo, error) {
	return []models.NetworkAdapterInfo{}, nil
}

func (sc *SystemCollector) collectHardware() (*models.HardwareInfo, error) {
	return &models.HardwareInfo{
		Processor:   runtime.GOARCH,
		MemorySize:  "unknown",
		BiosVersion: "unknown",
		Disks:       []string{},
	}, nil
}

func (sc *SystemCollector) getOSVersion() (string, string) {
	return runtime.GOOS, runtime.GOARCH
}

func (sc *SystemCollector) getOSExtraInfo() (majorVersion string, buildType string, installDate string) {
	return runtime.GOOS, "non-windows", ""
}
