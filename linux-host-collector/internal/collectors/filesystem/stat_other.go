//go:build !linux && !darwin

package filesystem

import "os"

func statOf(info os.FileInfo) fileStat {
	return fileStat{}
}
