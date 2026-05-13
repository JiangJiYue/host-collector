package collector

import (
	"context"
	"fmt"
	"os"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

const compSystem = "SystemCollector"

type SystemCollector struct{}

func NewSystemCollector() *SystemCollector {
	return &SystemCollector{}
}

func (sc *SystemCollector) Name() string {
	return "system"
}

func (sc *SystemCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info(compSystem, "开始采集系统信息...")

	type result struct {
		identity  *models.HostIdentityInfo
		resources *models.ResourceUsageInfo
		hardware  *models.HardwareInfo
		err       error
	}

	resultChan := make(chan result, 1)

	go func() {
		var r result

		identity, err := sc.collectIdentity()
		if err != nil {
			r.err = fmt.Errorf("failed to collect identity: %w", err)
			resultChan <- r
			return
		}
		r.identity = identity

		resources, err := sc.collectResources()
		if err != nil {
			r.err = fmt.Errorf("failed to collect resources: %w", err)
			resultChan <- r
			return
		}
		r.resources = resources

		hardware, err := sc.collectHardware()
		if err != nil {
			r.err = fmt.Errorf("failed to collect hardware: %w", err)
			resultChan <- r
			return
		}
		r.hardware = hardware

		resultChan <- r
	}()

	select {
	case r := <-resultChan:
		if r.err != nil {
			return nil, r.err
		}

		profile := &models.HostProfile{
			Identity:  *r.identity,
			Resources: *r.resources,
			Hardware:  *r.hardware,
		}

		utils.Info(compSystem, "系统信息采集完成")
		return profile, nil

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (sc *SystemCollector) collectIdentity() (*models.HostIdentityInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}

	networkAdapters, err := sc.collectNetworkAdapters()
	if err != nil {
		return nil, fmt.Errorf("failed to collect network adapters: %w", err)
	}

	osVersion, kernelVersion := sc.getOSVersion()
	majorVersion, buildType, installDate := sc.getOSExtraInfo()

	systemDir := os.Getenv("SystemRoot") + "\\system32"

	utils.Debug(compSystem, "系统信息: hostname=%s, user=%s, osVersion=%s", hostname, username, osVersion)

	return &models.HostIdentityInfo{
		Hostname:        hostname,
		NetworkAdapters: networkAdapters,
		Username:        username,
		OSVersion:       osVersion,
		MajorVersion:    majorVersion,
		BuildType:       buildType,
		KernelVersion:   kernelVersion,
		InstallDate:     installDate,
		SystemDirectory: systemDir,
	}, nil
}

func (sc *SystemCollector) collectNetworkAdapters() ([]models.NetworkAdapterInfo, error) {
	return sc.collectPlatformNetworkAdapters()
}

func (sc *SystemCollector) collectResources() (*models.ResourceUsageInfo, error) {
	cpuPercents, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercents) == 0 {
		utils.LogError(compSystem, "获取CPU使用率失败: %v", err)
		cpuPercents = []float64{0}
	}

	vmStat, err := mem.VirtualMemory()
	if err != nil {
		utils.LogError(compSystem, "获取内存信息失败: %v", err)
		vmStat = &mem.VirtualMemoryStat{}
	}

	var disksInfo []models.DiskUsageInfo
	partitions, err := disk.Partitions(true)
	if err != nil {
		utils.LogError(compSystem, "获取磁盘分区失败: %v", err)
	}
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		if usage.Total == 0 {
			continue
		}
		drive := p.Mountpoint
		if len(drive) >= 2 && drive[1] == ':' {
			drive = drive[:2]
		}
		disksInfo = append(disksInfo, models.DiskUsageInfo{
			Drive: drive,
			Usage: utils.Round1(usage.UsedPercent),
			Used:  utils.FormatGB(usage.Used),
			Total: utils.FormatGB(usage.Total),
		})
	}
	if len(disksInfo) == 0 {
		if usage, err := disk.Usage("C:\\"); err == nil {
			disksInfo = []models.DiskUsageInfo{{
				Drive: "C:",
				Usage: utils.Round1(usage.UsedPercent),
				Used:  utils.FormatGB(usage.Used),
				Total: utils.FormatGB(usage.Total),
			}}
		}
	}

	utils.Debug(compSystem, "资源采集: CPU=%.1f%%, 内存=%.1f%%, 磁盘=%d个", cpuPercents[0], vmStat.UsedPercent, len(disksInfo))

	return &models.ResourceUsageInfo{
		CPUUsage:    utils.Round1(cpuPercents[0]),
		MemoryUsage: utils.Round1(vmStat.UsedPercent),
		MemoryUsed:  utils.FormatGB(vmStat.Used),
		MemoryTotal: utils.FormatGB(vmStat.Total),
		Disks:       disksInfo,
	}, nil
}
