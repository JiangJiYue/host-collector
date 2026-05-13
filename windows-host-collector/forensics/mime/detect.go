package mime

import (
	"net/http"
	"path/filepath"
	"strings"
)

var extensionTypes = map[string]string{
	".json": "application/json",
	".txt":  "text/plain; charset=utf-8",
	".log":  "text/plain; charset=utf-8",
	".xml":  "application/xml",
}

func Detect(name string, header []byte) string {
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return "application/vnd.microsoft.portable-executable"
	}

	if ext := strings.ToLower(filepath.Ext(name)); ext != "" {
		if mimeType, ok := extensionTypes[ext]; ok {
			return mimeType
		}
	}

	return http.DetectContentType(header)
}
