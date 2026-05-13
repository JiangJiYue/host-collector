package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type webLogScanOptions struct {
	MaxDepth          int
	MaxFilesPerRoot   int
	MaxTotalFiles     int
	MaxSampleBytes    int64
	AllowedExtensions []string
}

type webLogFileCandidate struct {
	Path   string
	Size   int64
	Sample []byte
}

func scanWebLogCandidateFiles(roots []string, options webLogScanOptions) ([]webLogFileCandidate, error) {
	allowed := make(map[string]struct{}, len(options.AllowedExtensions))
	for _, ext := range options.AllowedExtensions {
		allowed[strings.ToLower(ext)] = struct{}{}
	}

	results := make([]webLogFileCandidate, 0)
	total := 0
	for _, root := range roots {
		rootCount := 0
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if path == root {
				return nil
			}
			if options.MaxDepth > 0 && pathDepth(root, path) > options.MaxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if options.MaxFilesPerRoot > 0 && rootCount >= options.MaxFilesPerRoot {
				return filepath.SkipAll
			}
			if options.MaxTotalFiles > 0 && total >= options.MaxTotalFiles {
				return filepath.SkipAll
			}
			ext := strings.ToLower(filepath.Ext(path))
			if len(allowed) > 0 {
				if _, ok := allowed[ext]; !ok {
					return nil
				}
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			sample, err := readFileSample(path, options.MaxSampleBytes)
			if err != nil {
				return nil
			}
			results = append(results, webLogFileCandidate{
				Path:   path,
				Size:   info.Size(),
				Sample: sample,
			})
			rootCount++
			total++
			return nil
		})
		if err != nil && err != filepath.SkipAll {
			return nil, fmt.Errorf("walk %s: %w", root, err)
		}
		if options.MaxTotalFiles > 0 && total >= options.MaxTotalFiles {
			break
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return results, nil
}

func pathDepth(root string, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(filepath.Separator)))
}

func readFileSample(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := make([]byte, maxBytes)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}
