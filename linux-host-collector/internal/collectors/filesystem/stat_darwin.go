//go:build darwin

package filesystem

import (
	"os"
	"syscall"
)

func statOf(info os.FileInfo) fileStat {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStat{}
	}
	return fileStat{
		Dev:      uint64(stat.Dev),
		Ino:      uint64(stat.Ino),
		UID:      stat.Uid,
		GID:      stat.Gid,
		Nlink:    uint64(stat.Nlink),
		Blocks:   stat.Blocks,
		AtimSec:  stat.Atimespec.Sec,
		AtimNsec: stat.Atimespec.Nsec,
		MtimSec:  stat.Mtimespec.Sec,
		MtimNsec: stat.Mtimespec.Nsec,
		CtimSec:  stat.Ctimespec.Sec,
		CtimNsec: stat.Ctimespec.Nsec,
	}
}
