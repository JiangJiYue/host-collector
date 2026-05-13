package collector

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"windows-host-collector/models"
	"windows-host-collector/utils"
)

type FileIdentityCollector struct {
	mu    sync.Mutex
	cache map[string]models.FileIdentity
}

func NewFileIdentityCollector() *FileIdentityCollector {
	return &FileIdentityCollector{
		cache: make(map[string]models.FileIdentity),
	}
}

func (c *FileIdentityCollector) CollectFile(path string, sources []string) models.FileIdentity {
	normalized := normalizeIdentityPath(path)
	if normalized == "" {
		normalized = path
	}

	c.mu.Lock()
	if identity, ok := c.cache[normalized]; ok {
		identity.EvidenceSources = mergeEvidenceSources(identity.EvidenceSources, sources)
		c.cache[normalized] = cloneFileIdentity(identity)
		c.mu.Unlock()
		return cloneFileIdentity(identity)
	}
	c.mu.Unlock()

	identity := models.FileIdentity{
		ID:              stableFileIdentityID(normalized),
		Path:            path,
		NormalizedPath:  normalized,
		EvidenceSources: append([]string(nil), sources...),
		SignatureState:  "unknown",
	}
	if base := filepath.Base(path); base != "." && base != string(filepath.Separator) {
		identity.Basename = base
		identity.Extension = filepath.Ext(base)
	}

	info, err := os.Stat(path)
	if err != nil {
		identity.CollectionError = err.Error()
		if isAccessDeniedError(err) {
			identity.HashState = "access_denied"
		} else {
			identity.HashState = "read_error"
		}
		c.storeIdentity(identity)
		return cloneFileIdentity(identity)
	}

	if info.IsDir() {
		identity.HashState = "skipped_not_file"
		identity.Size = info.Size()
		identity.ModifiedAt = utils.FormatTime(info.ModTime())
		c.storeIdentity(identity)
		return cloneFileIdentity(identity)
	}

	if identity.Basename == "" {
		identity.Basename = filepath.Base(path)
		identity.Extension = filepath.Ext(identity.Basename)
	}
	identity.Size = info.Size()
	identity.ModifiedAt = utils.FormatTime(info.ModTime())

	file, err := os.Open(path)
	if err != nil {
		identity.CollectionError = err.Error()
		if isAccessDeniedError(err) {
			identity.HashState = "access_denied"
		} else {
			identity.HashState = "read_error"
		}
		c.storeIdentity(identity)
		return cloneFileIdentity(identity)
	}
	defer file.Close()

	md5Hasher := md5.New()
	sha256Hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(md5Hasher, sha256Hasher), file); err != nil {
		identity.CollectionError = err.Error()
		if isAccessDeniedError(err) {
			identity.HashState = "access_denied"
		} else {
			identity.HashState = "read_error"
		}
		c.storeIdentity(identity)
		return cloneFileIdentity(identity)
	}

	identity.MD5 = hex.EncodeToString(md5Hasher.Sum(nil))
	identity.SHA256 = hex.EncodeToString(sha256Hasher.Sum(nil))
	identity.HashState = "completed"
	applyWindowsFileTrust(path, &identity)

	c.storeIdentity(identity)
	return cloneFileIdentity(identity)
}

func (c *FileIdentityCollector) Identities() []models.FileIdentity {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([]models.FileIdentity, 0, len(c.cache))
	for _, identity := range c.cache {
		result = append(result, cloneFileIdentity(identity))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].NormalizedPath == result[j].NormalizedPath {
			return result[i].ID < result[j].ID
		}
		return result[i].NormalizedPath < result[j].NormalizedPath
	})
	return result
}

func (c *FileIdentityCollector) storeIdentity(identity models.FileIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cache == nil {
		c.cache = make(map[string]models.FileIdentity)
	}
	if existing, ok := c.cache[identity.NormalizedPath]; ok {
		identity.EvidenceSources = mergeEvidenceSources(existing.EvidenceSources, identity.EvidenceSources)
	}
	c.cache[identity.NormalizedPath] = cloneFileIdentity(identity)
}

func cloneFileIdentity(identity models.FileIdentity) models.FileIdentity {
	clone := identity
	clone.EvidenceSources = append([]string(nil), identity.EvidenceSources...)
	return clone
}

func normalizeIdentityPath(path string) string {
	if path == "" {
		return ""
	}

	if isWindowsLikePath(path) {
		normalized := strings.ReplaceAll(path, `\`, "/")
		normalized = pathpkg.Clean(normalized)
		normalized = strings.ReplaceAll(normalized, "/", `\`)
		return strings.ToLower(normalized)
	}

	normalized := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		normalized = strings.ToLower(normalized)
	}
	return normalized
}

func stableFileIdentityID(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return "file-" + hex.EncodeToString(sum[:8])
}

func mergeEvidenceSources(existing, incoming []string) []string {
	if len(incoming) == 0 {
		return append([]string(nil), existing...)
	}

	seen := make(map[string]struct{}, len(existing)+len(incoming))
	result := make([]string, 0, len(existing)+len(incoming))
	for _, source := range existing {
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		result = append(result, source)
	}
	for _, source := range incoming {
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		result = append(result, source)
	}
	return result
}

func isWindowsLikePath(path string) bool {
	return strings.Contains(path, `\`) || strings.Contains(path, ":\\") || strings.HasPrefix(path, `\\`)
}

func isAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrPermission)
}
