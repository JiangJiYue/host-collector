package collector

import (
	"context"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// PrefetchCollector Prefetch 文件采集器
type PrefetchCollector struct{}

func NewPrefetchCollector() *PrefetchCollector {
	return &PrefetchCollector{}
}

func (pc *PrefetchCollector) Name() string {
	return "prefetch"
}

// PrefetchCollectionResult Prefetch 采集结果
type PrefetchCollectionResult struct {
	Entries []models.PrefetchEntry `json:"entries"`
	Total   int                    `json:"total"`
}

func (pc *PrefetchCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集 Prefetch 信息...")
	entries := pc.collectPrefetchEntries()

	utils.Info("Collector", "Prefetch 采集完成: %d个条目", len(entries))

	return &PrefetchCollectionResult{
		Entries: entries,
		Total:   len(entries),
	}, nil
}
