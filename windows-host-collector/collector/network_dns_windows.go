//go:build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	dnsapi                   = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable = dnsapi.NewProc("DnsGetCacheDataTable")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procCreateFileW          = kernel32.NewProc("CreateFileW")
	procReadFile             = kernel32.NewProc("ReadFile")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
)

type dnsCacheEntry struct {
	Next       *dnsCacheEntry
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
	Data       [4]uint8
}

const (
	GENERIC_READ          = 0x80000000
	OPEN_EXISTING         = 3
	FILE_SHARE_READ       = 0x00000001
	FILE_SHARE_WRITE      = 0x00000002
	FILE_ATTRIBUTE_NORMAL = 0x80
)

// readFileViaWin32 使用 Win32 API (CreateFile/ReadFile) 读取文件内容
func readFileViaWin32(filePath string) ([]byte, error) {
	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return nil, fmt.Errorf("路径编码失败: %w", err)
	}

	handle, _, callErr := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if handle == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("CreateFileW 失败: %v", callErr)
	}
	defer procCloseHandle.Call(handle)

	var buf [65536]byte
	var result []byte
	for {
		var bytesRead uint32
		ret, _, callErr := procReadFile.Call(
			handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&bytesRead)),
			0,
		)
		if ret == 0 {
			return nil, fmt.Errorf("ReadFile 失败: %v", callErr)
		}
		if bytesRead == 0 {
			break
		}
		result = append(result, buf[:bytesRead]...)
	}

	return result, nil
}

// parseHostsFromString 从字符串解析 Hosts 文件内容
func parseHostsFromString(content string) ([]models.HostsEntry, error) {
	var entries []models.HostsEntry
	lineNum := 0

	for _, raw := range strings.Split(content, "\n") {
		lineNum++
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 去掉行内注释: 例如 "1.1.1.1 a b # comment" → "1.1.1.1 a b"
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ip := parts[0]
		// 一个 IP 后面可能跟多个域名，全部展开
		for i := 1; i < len(parts); i++ {
			host := strings.TrimSpace(parts[i])
			if host == "" || strings.HasPrefix(host, "#") { // 再次防御
				continue
			}
			entries = append(entries, models.HostsEntry{
				ID:        fmt.Sprintf("host-%d-%d", lineNum, i),
				IPAddress: ip,
				Domain:    host,
			})
		}
	}

	if len(entries) == 0 {
		utils.Info("Collector", "Hosts 文件无有效条目")
		return []models.HostsEntry{}, nil
	}

	utils.Info("Collector", "Hosts 解析完成: %d 条目", len(entries))
	return entries, nil
}

// collectWindowsHostsEntries 通过 Win32 API 读取 Hosts 文件，失败时回退到注册表
func (nc *NetworkCollector) collectWindowsHostsEntries(ctx context.Context) ([]models.HostsEntry, error) {
	// 方法1: Win32 API (CreateFileW + ReadFile)
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	hostsPath := systemRoot + "\\System32\\drivers\\etc\\hosts"

	utils.Info("Collector", "尝试 Win32 API 读取 Hosts: %s", hostsPath)
	data, err := readFileViaWin32(hostsPath)
	if err == nil {
		utils.Info("Collector", "Win32 API 读取 Hosts 成功: %d 字节", len(data))
		return parseHostsFromString(string(data))
	}

	utils.LogError("Collector", "Win32 API 读取 Hosts 失败: %v", err)

	// 方法2: 尝试直接 os.ReadFile
	utils.Info("Collector", "尝试 os.ReadFile 读取 Hosts: %s", hostsPath)
	data, err = os.ReadFile(hostsPath)
	if err == nil {
		utils.Info("Collector", "os.ReadFile 读取 Hosts 成功: %d 字节", len(data))
		return parseHostsFromString(string(data))
	}
	utils.LogError("Collector", "os.ReadFile 读取 Hosts 失败: %v", err)

	// 方法3: 回退到注册表读取 Hosts 路径配置
	utils.Info("Collector", "回退到注册表读取 Hosts 路径")
	return nc.collectHostsFromRegistry()
}

// collectHostsFromRegistry 从注册表读取 Hosts 文件路径并尝试读取
func (nc *NetworkCollector) collectHostsFromRegistry() ([]models.HostsEntry, error) {
	// 注册表路径: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return nil, fmt.Errorf("打开注册表失败: %w", err)
	}
	defer key.Close()

	dbPath, _, err := key.GetStringValue("DataBasePath")
	if err != nil {
		return nil, fmt.Errorf("读取 DataBasePath 失败: %w", err)
	}

	// 展开环境变量 (%SystemRoot% 等)
	dbPath = os.ExpandEnv(dbPath)
	hostsPath := dbPath + "\\hosts"
	utils.Info("Collector", "注册表 Hosts 路径: %s", hostsPath)

	// 用 Win32 API 读取
	data, err := readFileViaWin32(hostsPath)
	if err != nil {
		return nil, fmt.Errorf("注册表路径读取 Hosts 失败: %w", err)
	}

	return parseHostsFromString(string(data))
}

func (nc *NetworkCollector) collectWindowsDNSCache(ctx context.Context) ([]models.DnsCacheRecord, error) {
	// 方法1: DnsGetCacheDataTable
	records, err := nc.collectDNSCacheViaAPI(ctx)
	if err == nil && len(records) > 0 {
		return records, nil
	}
	if err != nil {
		utils.LogError("Collector", "DnsGetCacheDataTable 调用失败: %v", err)
	} else {
		utils.Info("Collector", "DnsGetCacheDataTable 返回空缓存，尝试回退方案")
	}

	// 方法2: 隐藏调用 cmd /c ipconfig /displaydns
	records, err = nc.collectDNSCacheViaIPConfig(ctx)
	if err == nil {
		return records, nil
	}

	utils.LogError("Collector", "ipconfig /displaydns 获取 DNS 缓存失败: %v", err)
	return []models.DnsCacheRecord{}, nil
}

// collectDNSCacheViaAPI 通过 DnsGetCacheDataTable API 获取 DNS 缓存
func (nc *NetworkCollector) collectDNSCacheViaAPI(ctx context.Context) ([]models.DnsCacheRecord, error) {
	var head *dnsCacheEntry
	// DnsGetCacheDataTable returns non-zero (TRUE) on success and zero (FALSE) on failure.
	// The previous check inverted this logic, causing successful calls (ret=1) to be treated as failures.
	// See: Win32 BOOL semantics.
	ret, _, callErr := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if ret == 0 { // 0 indicates failure
		return nil, fmt.Errorf("DnsGetCacheDataTable 调用失败: %v", callErr)
	}

	var records []models.DnsCacheRecord
	idCounter := 0
	entry := head
	seen := make(map[string]bool)

	for entry != nil {
		name := windows.UTF16PtrToString(entry.Name)
		if name != "" && !seen[name] {
			seen[name] = true
			records = append(records, models.DnsCacheRecord{
				ID:         fmt.Sprintf("dns-%d", idCounter),
				Host:       name,
				RecordType: dnsTypeToString(entry.Type),
			})
			idCounter++
		}
		entry = entry.Next
	}

	if len(records) == 0 {
		utils.Info("Collector", "DNS缓存为空")
		return []models.DnsCacheRecord{}, nil
	}

	utils.Info("Collector", "DNS缓存采集完成: %d条", len(records))
	return records, nil
}

// collectDNSCacheViaIPConfig 隐藏调用 cmd /c ipconfig /displaydns 获取 DNS 缓存
func (nc *NetworkCollector) collectDNSCacheViaIPConfig(ctx context.Context) ([]models.DnsCacheRecord, error) {
	utils.Info("Collector", "尝试隐藏调用 ipconfig /displaydns 获取 DNS 缓存")

	cmd := exec.CommandContext(ctx, "cmd", "/C", "chcp 65001>nul && ipconfig /displaydns")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行 ipconfig /displaydns 失败: %w", err)
	}

	records := parseIPConfigDNSCache(string(output))

	utils.Info("Collector", "DNS 缓存通过 ipconfig 采集完成: %d条", len(records))
	return records, nil
}

func dnsTypeToString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
