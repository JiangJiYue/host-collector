//go:build linux

package filesystem

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	fsIocGetFlags   = 0x80086601
	fsImmutableFlag = 0x00000010
	fsAppendFlag    = 0x00000020
)

func collectSecurityAttributes(path string) linuxSecurityAttributes {
	attrs := securityAttributesFromXattrs(readXattrs(path))
	flags, ok := readFileFlags(path)
	if ok {
		attrs.Immutable = flags&fsImmutableFlag != 0
		attrs.AppendOnly = flags&fsAppendFlag != 0
	}
	return attrs
}

func readXattrs(path string) map[string][]byte {
	size, err := syscall.Listxattr(path, nil)
	if err != nil || size <= 0 {
		return nil
	}
	buffer := make([]byte, size)
	n, err := syscall.Listxattr(path, buffer)
	if err != nil || n <= 0 {
		return nil
	}
	result := map[string][]byte{}
	for _, nameBytes := range splitNULNames(buffer[:n]) {
		name := string(nameBytes)
		if name == "" {
			continue
		}
		valueSize, err := syscall.Getxattr(path, name, nil)
		if err != nil {
			continue
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			read, err := syscall.Getxattr(path, name, value)
			if err != nil {
				continue
			}
			value = value[:read]
		}
		result[name] = value
	}
	return result
}

func splitNULNames(buffer []byte) [][]byte {
	var names [][]byte
	start := 0
	for index, value := range buffer {
		if value != 0 {
			continue
		}
		if index > start {
			names = append(names, buffer[start:index])
		}
		start = index + 1
	}
	if start < len(buffer) {
		names = append(names, buffer[start:])
	}
	return names
}

func readFileFlags(path string) (uint32, bool) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, false
	}
	defer syscall.Close(fd)

	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(fsIocGetFlags), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		if !errors.Is(errno, syscall.ENOTTY) && !errors.Is(errno, syscall.EOPNOTSUPP) {
			return 0, false
		}
		return 0, false
	}
	return uint32(flags), true
}
