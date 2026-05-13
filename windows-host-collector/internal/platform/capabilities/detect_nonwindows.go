//go:build !windows

package capabilities

import "runtime"

func DetectWindowsFacts() WindowsFacts {
	return WindowsFacts{
		ProductName:  runtime.GOOS,
		Architecture: runtime.GOARCH,
		OSFamily:     OSFamilyWorkstation,
	}
}
