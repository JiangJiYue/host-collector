package appcore

import "path/filepath"

const ClientConfigDirName = ".host-collector"

func ClientConfigDir(homeDir string) string {
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ClientConfigDirName)
}

func ClientHistoryDir(homeDir string) string {
	configDir := ClientConfigDir(homeDir)
	if configDir == "" {
		return ""
	}
	return filepath.Join(configDir, "history")
}

func LinuxScanOutputPath(tempDir string, scanID string) string {
	return filepath.Join(tempDir, "linux-host-collector", scanID, "scan.json")
}
