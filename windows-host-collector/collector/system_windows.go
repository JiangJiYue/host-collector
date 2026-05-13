//go:build windows

package collector

import (
	"fmt"
	"net"
	"strings"
	"windows-host-collector/models"

	"github.com/StackExchange/wmi"
	"github.com/shirou/gopsutil/v3/host"
	"golang.org/x/sys/windows/registry"
)

type win32Processor struct {
	Name          string
	NumberOfCores uint32
	MaxClockSpeed uint32
}

type win32PhysicalMemory struct {
	Capacity     uint64
	Speed        uint32
	Manufacturer string
}

type win32BIOS struct {
	Name         string
	Manufacturer string
	Version      string
}

type win32DiskDrive struct {
	Model         string
	Size          uint64
	InterfaceType string
}

type win32NetworkAdapter struct {
	Index           uint32
	Name            string
	NetConnectionID string
	MACAddress      string
	PhysicalAdapter bool
	NetEnabled      *bool
}

type win32NetworkAdapterConfiguration struct {
	Index                uint32
	Description          string
	MACAddress           string
	IPAddress            []string
	DefaultIPGateway     []string
	DNSServerSearchOrder []string
	DHCPEnabled          *bool
	IPEnabled            bool
}

func normalizeMAC(mac string) string {
	return strings.ToUpper(strings.ReplaceAll(mac, ":", "-"))
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		result = append(result, v)
	}
	return result
}

func (sc *SystemCollector) collectPlatformNetworkAdapters() ([]models.NetworkAdapterInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var adapters []win32NetworkAdapter
	_ = wmi.Query("SELECT Index, Name, NetConnectionID, MACAddress, PhysicalAdapter, NetEnabled FROM Win32_NetworkAdapter", &adapters)
	adapterByMAC := make(map[string]win32NetworkAdapter, len(adapters))
	adapterByIndex := make(map[uint32]win32NetworkAdapter, len(adapters))
	for _, a := range adapters {
		adapterByIndex[a.Index] = a
		mac := normalizeMAC(a.MACAddress)
		if mac != "" {
			adapterByMAC[mac] = a
		}
	}

	var configs []win32NetworkAdapterConfiguration
	_ = wmi.Query("SELECT Index, Description, MACAddress, IPAddress, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled, IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", &configs)
	configByMAC := make(map[string]win32NetworkAdapterConfiguration, len(configs))
	configByIndex := make(map[uint32]win32NetworkAdapterConfiguration, len(configs))
	for _, c := range configs {
		configByIndex[c.Index] = c
		mac := normalizeMAC(c.MACAddress)
		if mac != "" {
			configByMAC[mac] = c
		}
	}

	result := make([]models.NetworkAdapterInfo, 0)
	for i, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		ips := make([]string, 0)
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
		if len(ips) == 0 && iface.HardwareAddr.String() == "" {
			continue
		}

		mac := normalizeMAC(iface.HardwareAddr.String())
		item := models.NetworkAdapterInfo{
			ID:          fmt.Sprintf("nic-%d", i),
			Name:        iface.Name,
			AdapterName: iface.Name,
			MACAddress:  iface.HardwareAddr.String(),
			IPAddresses: uniqueNonEmpty(ips),
		}

		var cfg win32NetworkAdapterConfiguration
		cfgFound := false
		if v, ok := configByMAC[mac]; ok {
			cfg = v
			cfgFound = true
		} else {
			for _, c := range configs {
				for _, ip := range c.IPAddress {
					for _, localIP := range item.IPAddresses {
						if ip == localIP {
							cfg = c
							cfgFound = true
							break
						}
					}
					if cfgFound {
						break
					}
				}
				if cfgFound {
					break
				}
			}
		}
		if cfgFound {
			item.Description = cfg.Description
			item.DefaultGateways = uniqueNonEmpty(cfg.DefaultIPGateway)
			item.DNSServers = uniqueNonEmpty(cfg.DNSServerSearchOrder)
			item.DHCPEnabled = cfg.DHCPEnabled
			if item.MACAddress == "" {
				item.MACAddress = cfg.MACAddress
			}
			item.IPAddresses = uniqueNonEmpty(append(item.IPAddresses, cfg.IPAddress...))
		}

		var ad win32NetworkAdapter
		adFound := false
		if cfgFound {
			if v, ok := adapterByIndex[cfg.Index]; ok {
				ad = v
				adFound = true
			}
		}
		if !adFound {
			if v, ok := adapterByMAC[mac]; ok {
				ad = v
				adFound = true
			}
		}
		if adFound {
			if ad.NetConnectionID != "" {
				item.Name = ad.NetConnectionID
			}
			if ad.Name != "" {
				item.AdapterName = ad.Name
			}
			item.PhysicalAdapter = &ad.PhysicalAdapter
			item.NetEnabled = ad.NetEnabled
		}

		result = append(result, item)
	}

	return result, nil
}

func (sc *SystemCollector) collectHardware() (*models.HardwareInfo, error) {
	// 查询 CPU
	var processors []win32Processor
	wmi.Query("SELECT Name, NumberOfCores, MaxClockSpeed FROM Win32_Processor", &processors)

	processorName := "Unknown"
	if len(processors) > 0 {
		processorName = fmt.Sprintf("%s (%d cores, %d MHz)",
			processors[0].Name, processors[0].NumberOfCores, processors[0].MaxClockSpeed)
	}

	// 查询内存
	var memories []win32PhysicalMemory
	wmi.Query("SELECT Capacity, Speed, Manufacturer FROM Win32_PhysicalMemory", &memories)

	memorySize := "Unknown"
	if len(memories) > 0 {
		var totalBytes uint64
		for _, m := range memories {
			totalBytes += m.Capacity
		}
		memorySize = fmt.Sprintf("%d GB", totalBytes/(1024*1024*1024))
	}

	// 查询 BIOS
	var bios []win32BIOS
	wmi.Query("SELECT Name, Manufacturer, Version FROM Win32_BIOS", &bios)

	biosVersion := "Unknown"
	if len(bios) > 0 {
		biosVersion = fmt.Sprintf("%s %s (%s)", bios[0].Manufacturer, bios[0].Name, bios[0].Version)
	}

	// 查询磁盘
	var disks []win32DiskDrive
	wmi.Query("SELECT Model, Size, InterfaceType FROM Win32_DiskDrive", &disks)

	diskInfo := make([]string, 0, len(disks))
	for _, d := range disks {
		sizeGB := d.Size / (1024 * 1024 * 1024)
		diskInfo = append(diskInfo, fmt.Sprintf("%s (%d GB, %s)", d.Model, sizeGB, d.InterfaceType))
	}

	return &models.HardwareInfo{
		Processor:   processorName,
		MemorySize:  memorySize,
		BiosVersion: biosVersion,
		Disks:       diskInfo,
	}, nil
}

func (sc *SystemCollector) getOSVersion() (string, string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		hostInfo, _ := host.Info()
		if hostInfo != nil {
			return hostInfo.Platform + " " + hostInfo.PlatformVersion, hostInfo.KernelVersion
		}
		return "Unknown", "Unknown"
	}
	defer key.Close()

	productName, _, _ := key.GetStringValue("ProductName")
	currentBuild, _, _ := key.GetStringValue("CurrentBuild")
	ubr, _, _ := key.GetStringValue("UBR")

	version := fmt.Sprintf("%s Build %s.%s", productName, currentBuild, ubr)

	kernelVersion := "Unknown"
	hostInfo, err := host.Info()
	if err == nil {
		kernelVersion = hostInfo.KernelVersion
	}

	return version, kernelVersion
}

func (sc *SystemCollector) getOSExtraInfo() (majorVersion string, buildType string, installDate string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", ""
	}
	defer key.Close()

	majorVersion, _, _ = key.GetStringValue("CurrentMajorVersionNumber")
	if majorVersion == "" {
		majorVersion, _, _ = key.GetStringValue("CurrentVersion")
	}

	buildType, _, _ = key.GetStringValue("BuildBranch")
	if buildType == "" {
		buildType, _, _ = key.GetStringValue("InstallationType")
	}

	installDateInt, _, err := key.GetIntegerValue("InstallDate")
	if err == nil {
		installDate = fmt.Sprintf("%d", installDateInt)
	}

	return majorVersion, buildType, installDate
}
