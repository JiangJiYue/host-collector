//go:build windows

package collector

import (
	"os"
	"path/filepath"
)

type browserProfileMode string

const (
	chromiumProfileMode browserProfileMode = "chromium"
	firefoxProfileMode  browserProfileMode = "firefox"
)

type browserTimeMode string

const (
	chromiumTimeMode browserTimeMode = "chromium"
	firefoxTimeMode  browserTimeMode = "firefox"
)

type browserDefinition struct {
	Name              string
	RootPath          string
	HistoryFile       string
	ProfileMode       browserProfileMode
	TimeMode          browserTimeMode
	Query             string
	MaxRowsPerProfile int
}

func joinWindowsRoot(base string, elems ...string) string {
	if base == "" {
		return ""
	}
	parts := append([]string{base}, elems...)
	return filepath.Join(parts...)
}

func browserDefinitions() []browserDefinition {
	localAppData := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")

	return []browserDefinition{
		{
			Name:              "Chrome",
			RootPath:          joinWindowsRoot(localAppData, "Google", "Chrome", "User Data"),
			HistoryFile:       "History",
			ProfileMode:       chromiumProfileMode,
			TimeMode:          chromiumTimeMode,
			Query:             chromiumHistoryQuery,
			MaxRowsPerProfile: 2000,
		},
		{
			Name:              "Edge",
			RootPath:          joinWindowsRoot(localAppData, "Microsoft", "Edge", "User Data"),
			HistoryFile:       "History",
			ProfileMode:       chromiumProfileMode,
			TimeMode:          chromiumTimeMode,
			Query:             chromiumHistoryQuery,
			MaxRowsPerProfile: 2000,
		},
		{
			Name:              "Brave",
			RootPath:          joinWindowsRoot(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
			HistoryFile:       "History",
			ProfileMode:       chromiumProfileMode,
			TimeMode:          chromiumTimeMode,
			Query:             chromiumHistoryQuery,
			MaxRowsPerProfile: 2000,
		},
		{
			Name:              "Chromium",
			RootPath:          joinWindowsRoot(localAppData, "Chromium", "User Data"),
			HistoryFile:       "History",
			ProfileMode:       chromiumProfileMode,
			TimeMode:          chromiumTimeMode,
			Query:             chromiumHistoryQuery,
			MaxRowsPerProfile: 2000,
		},
		{
			Name:              "Vivaldi",
			RootPath:          joinWindowsRoot(localAppData, "Vivaldi", "User Data"),
			HistoryFile:       "History",
			ProfileMode:       chromiumProfileMode,
			TimeMode:          chromiumTimeMode,
			Query:             chromiumHistoryQuery,
			MaxRowsPerProfile: 2000,
		},
		{
			Name:              "Firefox",
			RootPath:          joinWindowsRoot(appData, "Mozilla", "Firefox", "Profiles"),
			HistoryFile:       "places.sqlite",
			ProfileMode:       firefoxProfileMode,
			TimeMode:          firefoxTimeMode,
			Query:             firefoxHistoryQuery,
			MaxRowsPerProfile: 2000,
		},
	}
}
