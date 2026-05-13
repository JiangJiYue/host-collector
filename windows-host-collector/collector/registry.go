package collector

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// RegistryCollector 定向注册表取证采集器
type RegistryCollector struct {
	maxDepth      int
	progressEvery int
	progress      func(RegistryProgress)
}

// NewRegistryCollector 创建定向注册表取证采集器
func NewRegistryCollector() *RegistryCollector {
	return &RegistryCollector{
		maxDepth:      30,
		progressEvery: 10000,
	}
}

func (rc *RegistryCollector) WithProgress(fn func(RegistryProgress)) *RegistryCollector {
	rc.progress = fn
	return rc
}

func (rc *RegistryCollector) report(progress RegistryProgress) {
	if rc.progress != nil {
		rc.progress(progress)
	}
}

// Name 返回采集器名称
func (rc *RegistryCollector) Name() string {
	return "registry"
}

// Collect 采集注册表信息
func (rc *RegistryCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集注册表信息...")

	values := rc.collectAllRoots(ctx)

	utils.Info("Collector", "注册表采集完成: %d个值", len(values))

	return &RegistryCollectionResult{
		Values: values,
		Total:  len(values),
	}, nil
}

// RegistryCollectionResult 注册表采集结果
type RegistryCollectionResult struct {
	Values []models.RegistryValue `json:"values"`
	Total  int                    `json:"total"`
}

type RegistryTarget struct {
	Root               string
	Path               string
	CollectionCategory string
	RiskPurpose        string
	Recursive          bool
	ValueNames         []string
}

func defaultTargetedRegistryPlan() []RegistryTarget {
	plan := []RegistryTarget{
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, CollectionCategory: "persistence", RiskPurpose: "run_key"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, CollectionCategory: "persistence", RiskPurpose: "run_once_key"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, CollectionCategory: "persistence", RiskPurpose: "run_key"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, CollectionCategory: "persistence", RiskPurpose: "run_once_key"},
		{Root: "HKEY_CURRENT_USER", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, CollectionCategory: "persistence", RiskPurpose: "run_key"},
		{Root: "HKEY_CURRENT_USER", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, CollectionCategory: "persistence", RiskPurpose: "run_once_key"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, CollectionCategory: "persistence", RiskPurpose: "policies_explorer_run"},
		{Root: "HKEY_CURRENT_USER", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, CollectionCategory: "persistence", RiskPurpose: "policies_explorer_run"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Services`, CollectionCategory: "service", RiskPurpose: "service_image_and_dll", Recursive: true, ValueNames: []string{"ImagePath", "Type", "Start", "ObjectName", "Description", "FailureActions", "ServiceDll"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`, CollectionCategory: "service", RiskPurpose: "svchost_group"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, CollectionCategory: "persistence", RiskPurpose: "winlogon_hijack", ValueNames: []string{"Shell", "Userinit", "Notify", "AppSetup", "Taskman", "GinaDLL", "VMApplet"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, CollectionCategory: "ifeo", RiskPurpose: "image_file_execution_options", Recursive: true, ValueNames: []string{"Debugger", "GlobalFlag", "VerifierDlls"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, CollectionCategory: "persistence", RiskPurpose: "appinit_dlls", ValueNames: []string{"AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Control\Session Manager`, CollectionCategory: "persistence", RiskPurpose: "session_manager", ValueNames: []string{"BootExecute", "Execute", "SetupExecute", "PendingFileRenameOperations", "KnownDlls"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`, CollectionCategory: "persistence", RiskPurpose: "appcert_dlls"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, CollectionCategory: "hijack", RiskPurpose: "known_dlls"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Control\Lsa`, CollectionCategory: "credential_access", RiskPurpose: "lsa_security_packages", ValueNames: []string{"Authentication Packages", "Notification Packages", "Security Packages", "RunAsPPL"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Control\SecurityProviders`, CollectionCategory: "credential_access", RiskPurpose: "security_providers", ValueNames: []string{"SecurityProviders"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`, CollectionCategory: "persistence", RiskPurpose: "shell_execute_hooks"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`, CollectionCategory: "persistence", RiskPurpose: "approved_shell_extensions"},
		{Root: "HKEY_CURRENT_USER", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`, CollectionCategory: "persistence", RiskPurpose: "approved_shell_extensions"},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, CollectionCategory: "browser_hijack", RiskPurpose: "browser_helper_objects", Recursive: true},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, CollectionCategory: "browser_hijack", RiskPurpose: "browser_helper_objects", Recursive: true},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`, CollectionCategory: "persistence", RiskPurpose: "scheduled_task_cache", Recursive: true, ValueNames: []string{"Path", "Hash", "Id", "Index", "SD"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\PowerShell`, CollectionCategory: "script_execution", RiskPurpose: "powershell_configuration", Recursive: true},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, CollectionCategory: "network_hijack", RiskPurpose: "internet_settings", ValueNames: []string{"ProxyEnable", "ProxyServer", "AutoConfigURL", "AutoDetect"}},
		{Root: "HKEY_CURRENT_USER", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, CollectionCategory: "network_hijack", RiskPurpose: "internet_settings", ValueNames: []string{"ProxyEnable", "ProxyServer", "AutoConfigURL", "AutoDetect"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SYSTEM\CurrentControlSet\Control\Terminal Server`, CollectionCategory: "remote_access", RiskPurpose: "terminal_server", ValueNames: []string{"fDenyTSConnections", "UserAuthentication", "SecurityLayer"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, CollectionCategory: "software_inventory", RiskPurpose: "uninstall_entries", Recursive: true, ValueNames: []string{"DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "InstallDate", "UninstallString", "QuietUninstallString"}},
		{Root: "HKEY_LOCAL_MACHINE", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, CollectionCategory: "software_inventory", RiskPurpose: "uninstall_entries", Recursive: true, ValueNames: []string{"DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "InstallDate", "UninstallString", "QuietUninstallString"}},
		{Root: "HKEY_CURRENT_USER", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, CollectionCategory: "software_inventory", RiskPurpose: "uninstall_entries", Recursive: true, ValueNames: []string{"DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "InstallDate", "UninstallString", "QuietUninstallString"}},
	}

	for _, assoc := range []struct {
		extension string
		progID    string
	}{
		{`.exe`, `exefile`},
		{`.com`, `comfile`},
		{`.bat`, `batfile`},
		{`.cmd`, `cmdfile`},
		{`.ps1`, `Microsoft.PowerShellScript.1`},
		{`.vbs`, `VBSFile`},
		{`.js`, `JSFile`},
		{`.jse`, `JSEFile`},
		{`.wsf`, `WSFFile`},
		{`.msc`, `MSCFile`},
		{`.lnk`, `lnkfile`},
	} {
		plan = append(plan,
			RegistryTarget{Root: "HKEY_CLASSES_ROOT", Path: assoc.extension, CollectionCategory: "file_association", RiskPurpose: "extension_association"},
			RegistryTarget{Root: "HKEY_CLASSES_ROOT", Path: assoc.progID + `\shell\open\command`, CollectionCategory: "file_association", RiskPurpose: "open_command"},
		)
	}

	return plan
}

func containsRegistryTarget(plan []RegistryTarget, root, path string) bool {
	for _, target := range plan {
		if strings.EqualFold(target.Root, root) && strings.EqualFold(target.Path, path) {
			return true
		}
	}
	return false
}

var registryReferencedPathPattern = regexp.MustCompile(`(?i)(?:[A-Z]:|%[A-Z0-9_() ]+%)\\[^"'<>|]+?\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|jse|wsf|msc|lnk)(?:,\w+)?`)

func extractReferencedPathFromRegistryValue(value models.RegistryValue) *string {
	data := strings.TrimSpace(value.Data)
	if data == "" {
		return nil
	}

	matches := registryReferencedPathPattern.FindAllString(data, -1)
	for _, match := range matches {
		path := cleanRegistryReferencedPath(match)
		if looksExecutableRegistryReference(path) {
			return utils.StringPtr(path)
		}
	}

	return nil
}

func cleanRegistryReferencedPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)
	if idx := strings.Index(path, ","); idx >= 0 && looksExecutableRegistryReference(path[:idx]) {
		path = path[:idx]
	}
	return strings.TrimSpace(path)
}

func looksExecutableRegistryReference(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".msc", ".lnk":
		return true
	default:
		return false
	}
}

// collectRegistryPath 采集指定路径的注册表值（由 build tag 实现）
// collectAllRoots 采集定向注册表取证路径（由 build tag 实现）
