package filesystem

type fileStat struct {
	Dev      uint64
	Ino      uint64
	UID      uint32
	GID      uint32
	Nlink    uint64
	Blocks   int64
	AtimSec  int64
	AtimNsec int64
	MtimSec  int64
	MtimNsec int64
	CtimSec  int64
	CtimNsec int64
}
