//go:build windows

package volume

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type Reader struct {
	path string
	file *os.File
}

func NormalizeVolumePath(volume string) (string, error) {
	trimmed := strings.TrimSpace(volume)
	if trimmed == "" {
		return "", fmt.Errorf("volume path is empty")
	}
	if strings.HasPrefix(trimmed, `\\.\`) {
		return trimmed, nil
	}
	if len(trimmed) == 3 && trimmed[1] == ':' && (trimmed[2] == '\\' || trimmed[2] == '/') {
		trimmed = trimmed[:2]
	}
	if len(trimmed) == 1 {
		trimmed += ":"
	}
	if len(trimmed) == 2 && trimmed[1] == ':' {
		return `\\.\` + strings.ToUpper(trimmed), nil
	}
	return "", fmt.Errorf("unsupported volume path %q", volume)
}

func Open(volume string) (*Reader, error) {
	path, err := NormalizeVolumePath(volume)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &Reader{path: path, file: file}, nil
}

func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if r == nil || r.file == nil {
		return 0, io.ErrClosedPipe
	}
	return r.file.ReadAt(p, off)
}

func (r *Reader) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.file.Close()
}
