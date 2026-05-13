//go:build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows/registry"
)

// ServiceCollector 服务、驱动、启动项采集器
type ServiceCollector struct{}

// NewServiceCollector 创建服务采集器
func NewServiceCollector() *ServiceCollector {
	return &ServiceCollector{}
}

// Name 返回采集器名称
func (sc *ServiceCollector) Name() string {
	return "service"
}

// Collect 采集服务信息
func (sc *ServiceCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集服务信息...")

	// 并发采集各项服务信息
	type result struct {
		services []models.ServiceItem
		drivers  []models.DriverItem
		startups []models.StartupItem
		err      error
	}

	resultChan := make(chan result, 1)

	go func() {
		var r result

		// 采集Windows服务
		services, err := sc.collectServices(ctx)
		if err != nil {
			r.err = fmt.Errorf("failed to collect services: %w", err)
			resultChan <- r
			return
		}
		r.services = services

		// 采集驱动程序（非致命错误）
		drivers, err := sc.collectDrivers(ctx)
		if err != nil {
			utils.LogError("Collector", "驱动采集失败: %v", err)
			drivers = []models.DriverItem{}
		}
		r.drivers = drivers

		// 采集启动项（非致命错误）
		startups, err := sc.collectStartups(ctx)
		if err != nil {
			utils.LogError("Collector", "启动项采集失败: %v", err)
			startups = []models.StartupItem{}
		}
		r.startups = startups

		resultChan <- r
	}()

	// 等待采集完成或超时
	select {
	case r := <-resultChan:
		if r.err != nil {
			return nil, r.err
		}

		utils.Info("Collector", "服务信息采集完成: %d个服务, %d个驱动, %d个启动项",
			len(r.services), len(r.drivers), len(r.startups))

		return &ServiceCollectionResult{
			Services: r.services,
			Drivers:  r.drivers,
			Startups: r.startups,
		}, nil

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ServiceCollectionResult 服务采集结果
type ServiceCollectionResult struct {
	Services []models.ServiceItem `json:"services"`
	Drivers  []models.DriverItem  `json:"drivers"`
	Startups []models.StartupItem `json:"startups"`
}

// Win32Service WMI Win32_Service结构
type Win32Service struct {
	Name        string
	DisplayName string
	PathName    *string
	StartName   *string
	Description *string
	State       string
	ServiceType string
	Started     bool
	StartMode   string
	ProcessId   uint32
}

// collectServices 采集Windows服务
func (sc *ServiceCollector) collectServices(ctx context.Context) ([]models.ServiceItem, error) {
	var services []Win32Service
	query := "SELECT Name, DisplayName, PathName, StartName, Description, State, ServiceType, Started, StartMode, ProcessId FROM Win32_Service"

	err := wmi.Query(query, &services)
	if err != nil {
		utils.LogError("Collector", "WMI查询Win32_Service失败: %v", err)
		return nil, err
	}

	// 转换为我们的模型
	result := make([]models.ServiceItem, 0, len(services))
	for i, s := range services {
		// 获取服务依赖
		dependencies := sc.getServiceDependencies(s.Name)

		// 提取DLL路径（如果是svchost.exe）
		var dllPath *string
		if s.PathName != nil && strings.Contains(strings.ToLower(*s.PathName), "svchost.exe") {
			dllPath = sc.extractDllPath(s.Name)
		}

		service := models.ServiceItem{
			ID:           fmt.Sprintf("service-%d", i),
			Name:         s.Name,
			DisplayName:  s.DisplayName,
			Account:      s.StartName,
			Path:         s.PathName,
			Description:  s.Description,
			DllPath:      dllPath,
			Dependencies: dependencies,
		}
		result = append(result, service)
	}

	return result, nil
}

// getServiceDependencies 获取服务依赖
func (sc *ServiceCollector) getServiceDependencies(serviceName string) []string {
	// 从注册表读取服务依赖
	keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\%s`, serviceName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return []string{}
	}
	defer key.Close()

	// 读取DependOnService值
	deps, _, err := key.GetStringsValue("DependOnService")
	if err != nil {
		return []string{}
	}

	return deps
}

// extractDllPath 提取服务DLL路径
func (sc *ServiceCollector) extractDllPath(serviceName string) *string {
	// 从注册表读取ServiceDll
	keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\%s\Parameters`, serviceName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	dllPath, _, err := key.GetStringValue("ServiceDll")
	if err != nil {
		return nil
	}

	// 展开环境变量
	expanded := os.ExpandEnv(dllPath)
	return &expanded
}

// Win32SystemDriver WMI Win32_SystemDriver结构
type Win32SystemDriver struct {
	Name        string
	DisplayName string
	PathName    *string
	Description *string
	State       string
	Started     bool
	StartMode   string
}

// collectDrivers 采集驱动程序
func (sc *ServiceCollector) collectDrivers(ctx context.Context) ([]models.DriverItem, error) {
	var drivers []Win32SystemDriver
	query := "SELECT Name, DisplayName, PathName, Description, State, Started, StartMode FROM Win32_SystemDriver"

	err := wmi.Query(query, &drivers)
	if err != nil {
		utils.LogError("Collector", "WMI查询Win32_SystemDriver失败: %v", err)
		return nil, err
	}

	// 转换为我们的模型
	result := make([]models.DriverItem, 0, len(drivers))
	for i, d := range drivers {
		// 获取驱动依赖
		dependencies := sc.getServiceDependencies(d.Name)

		driver := models.DriverItem{
			ID:           fmt.Sprintf("driver-%d", i),
			Name:         d.Name,
			DisplayName:  d.DisplayName,
			Path:         d.PathName,
			Description:  d.Description,
			Dependencies: dependencies,
		}
		result = append(result, driver)
	}

	return result, nil
}

// Win32StartupCommand WMI Win32_StartupCommand结构
type Win32StartupCommand struct {
	Caption  string
	Command  string
	User     *string
	Location string
}

// collectStartups 采集启动项
func (sc *ServiceCollector) collectStartups(ctx context.Context) ([]models.StartupItem, error) {
	startupItems := make([]models.StartupItem, 0)

	// 1. WMI查询Win32_StartupCommand
	wmiStartups, err := sc.collectWMIStartups()
	if err != nil {
		utils.LogError("Collector", "WMI启动项采集失败: %v", err)
	} else {
		startupItems = append(startupItems, wmiStartups...)
	}

	// 2. 注册表启动项
	regStartups := sc.collectRegistryStartups()
	startupItems = append(startupItems, regStartups...)

	// 3. 启动文件夹
	folderStartups := sc.collectStartupFolderItems()
	startupItems = append(startupItems, folderStartups...)

	// 如果没有采集到任何启动项，返回空结果
	return startupItems, nil
}

// collectWMIStartups 通过WMI采集启动项
func (sc *ServiceCollector) collectWMIStartups() ([]models.StartupItem, error) {
	var startupCmds []Win32StartupCommand
	query := "SELECT Caption, Command, User, Location FROM Win32_StartupCommand"

	err := wmi.Query(query, &startupCmds)
	if err != nil {
		return nil, fmt.Errorf("WMI query failed: %w", err)
	}

	result := make([]models.StartupItem, 0, len(startupCmds))
	for i, cmd := range startupCmds {
		// 判断安全状态
		safetyStatus := sc.determineSafetyStatus(cmd.Command)

		// 判断运行状态（简化实现，实际需要检查进程）
		runStatus := models.StartupStopped

		// 提取公司信息
		company := sc.extractCompanyInfo(cmd.Command)

		startup := models.StartupItem{
			ID:           fmt.Sprintf("startup-wmi-%d", i),
			Name:         cmd.Caption,
			SafetyStatus: safetyStatus,
			Description:  utils.StringPtr(cmd.Command),
			Company:      company,
			RunStatus:    runStatus,
			Path:         utils.StringPtr(cmd.Command),
			Category:     sc.categorizeStartup(cmd.Location),
		}
		result = append(result, startup)
	}

	return result, nil
}

// collectRegistryStartups 从注册表采集启动项
func (sc *ServiceCollector) collectRegistryStartups() []models.StartupItem {
	startups := make([]models.StartupItem, 0)

	// 注册表启动项路径
	regPaths := []struct {
		root     registry.Key
		path     string
		category string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "登录"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "登录"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "登录"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "登录"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "登录"},
	}

	idCounter := 0
	for _, regPath := range regPaths {
		key, err := registry.OpenKey(regPath.root, regPath.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// 读取所有值
		valueNames, err := key.ReadValueNames(0)
		if err != nil {
			key.Close()
			continue
		}

		for _, name := range valueNames {
			value, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}

			safetyStatus := sc.determineSafetyStatus(value)
			company := sc.extractCompanyInfo(value)

			startup := models.StartupItem{
				ID:           fmt.Sprintf("startup-reg-%d", idCounter),
				Name:         name,
				SafetyStatus: safetyStatus,
				Company:      company,
				RunStatus:    models.StartupStopped,
				Path:         utils.StringPtr(value),
				Category:     regPath.category,
			}
			startups = append(startups, startup)
			idCounter++
		}

		key.Close()
	}

	return startups
}

// collectStartupFolderItems 从启动文件夹采集启动项
func (sc *ServiceCollector) collectStartupFolderItems() []models.StartupItem {
	startups := make([]models.StartupItem, 0)

	// 启动文件夹路径
	startupFolders := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	}

	idCounter := 0
	for _, folder := range startupFolders {
		files, err := os.ReadDir(folder)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			fullPath := filepath.Join(folder, file.Name())
			safetyStatus := sc.determineSafetyStatus(fullPath)

			startup := models.StartupItem{
				ID:           fmt.Sprintf("startup-folder-%d", idCounter),
				Name:         file.Name(),
				SafetyStatus: safetyStatus,
				RunStatus:    models.StartupStopped,
				Path:         utils.StringPtr(fullPath),
				Category:     "登录",
			}
			startups = append(startups, startup)
			idCounter++
		}
	}

	return startups
}

// determineSafetyStatus 判断启动项安全状态
func (sc *ServiceCollector) determineSafetyStatus(path string) models.StartupSafetyStatus {
	if path == "" {
		return models.StartupUnsigned
	}

	lowerPath := strings.ToLower(path)

	// 系统路径下的认为是系统启动项
	if strings.Contains(lowerPath, "\\windows\\") ||
		strings.Contains(lowerPath, "\\system32\\") ||
		strings.Contains(lowerPath, "\\syswow64\\") {
		return models.StartupSystem
	}

	// Program Files下的认为是已签名
	if strings.Contains(lowerPath, "\\program files\\") ||
		strings.Contains(lowerPath, "\\program files (x86)\\") {
		return models.StartupSigned
	}

	// TODO: 实际应该检查数字签名
	// 可以使用 Windows Authenticode API 验证文件签名

	return models.StartupUnsigned
}

// extractCompanyInfo 提取公司信息
func (sc *ServiceCollector) extractCompanyInfo(path string) *string {
	// TODO: 实际应该读取文件的版本信息
	// 可以使用 Windows Version Info API

	// 简化实现：从路径推断
	lowerPath := strings.ToLower(path)

	if strings.Contains(lowerPath, "microsoft") {
		return utils.StringPtr("Microsoft Corporation")
	}
	if strings.Contains(lowerPath, "google") {
		return utils.StringPtr("Google Inc.")
	}
	if strings.Contains(lowerPath, "adobe") {
		return utils.StringPtr("Adobe Systems")
	}

	return nil
}

// categorizeStartup 对启动项分类
func (sc *ServiceCollector) categorizeStartup(location string) string {
	location = strings.ToLower(location)

	if strings.Contains(location, "driver") {
		return "驱动程序"
	}
	if strings.Contains(location, "logon") || strings.Contains(location, "login") {
		return "登录"
	}
	if strings.Contains(location, "service") {
		return "系统服务"
	}
	if strings.Contains(location, "task") || strings.Contains(location, "scheduled") {
		return "计划任务"
	}
	if strings.Contains(location, "run") {
		return "登录"
	}
	if strings.Contains(location, "startup") {
		return "登录"
	}

	return "其他"
}
