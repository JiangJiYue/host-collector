//go:build !windows

package collector

import (
	"context"
	"windows-host-collector/forensics/filesystem"
)

func (c *ForensicFileSystemCollector) Collect(ctx context.Context) (interface{}, error) {
	_ = ctx
	return &ForensicFileSystemResult{
		Volumes:        []filesystem.VolumeInfo{},
		DirectoryNodes: []filesystem.DirectoryNode{},
		FileEntries:    []filesystem.FileEntry{},
		TimelineEvents: []filesystem.TimelineEvent{},
	}, nil
}
