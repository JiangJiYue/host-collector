//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"strings"
)

func discoverChromiumProfiles(root, historyFile string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	profiles := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name != "Default" && !strings.HasPrefix(name, "Profile ") {
			continue
		}
		profilePath := filepath.Join(root, name)
		if _, err := os.Stat(filepath.Join(profilePath, historyFile)); err != nil {
			continue
		}
		profiles = append(profiles, profilePath)
	}
	return profiles
}

func discoverFirefoxProfiles(root, historyFile string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	profiles := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profilePath := filepath.Join(root, entry.Name())
		if _, err := os.Stat(filepath.Join(profilePath, historyFile)); err != nil {
			continue
		}
		profiles = append(profiles, profilePath)
	}
	return profiles
}
