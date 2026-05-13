package contracts

import "strings"

type Platform string

const (
	PlatformUnknown Platform = "unknown"
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
)

type Architecture string

const (
	ArchitectureUnknown Architecture = "unknown"
	ArchitectureAMD64   Architecture = "amd64"
	ArchitectureARM64   Architecture = "arm64"
	ArchitectureX86     Architecture = "x86"
	ArchitectureARM     Architecture = "arm"
)

type PlatformExtensions struct {
	Windows map[string]any `json:"windows,omitempty"`
	Linux   map[string]any `json:"linux,omitempty"`
}

type PlatformFacts struct {
	Platform     Platform           `json:"platform"`
	Architecture Architecture       `json:"architecture"`
	OSName       string             `json:"osName,omitempty"`
	OSVersion    string             `json:"osVersion,omitempty"`
	Kernel       string             `json:"kernel,omitempty"`
	Hostname     string             `json:"hostname,omitempty"`
	Extensions   PlatformExtensions `json:"platformExtensions,omitempty"`
}

func NormalizeArchitecture(value string) Architecture {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x86_64":
		return ArchitectureAMD64
	case "arm64", "aarch64":
		return ArchitectureARM64
	case "386", "i386", "i686", "x86":
		return ArchitectureX86
	case "arm":
		return ArchitectureARM
	default:
		return ArchitectureUnknown
	}
}
