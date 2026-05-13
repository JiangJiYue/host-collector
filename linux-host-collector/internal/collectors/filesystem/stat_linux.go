//go:build linux

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
		AtimSec:  stat.Atim.Sec,
		AtimNsec: stat.Atim.Nsec,
		MtimSec:  stat.Mtim.Sec,
		MtimNsec: stat.Mtim.Nsec,
		CtimSec:  stat.Ctim.Sec,
		CtimNsec: stat.Ctim.Nsec,
	}
}
