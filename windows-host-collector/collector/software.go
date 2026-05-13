package collector

import (
	"context"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// SoftwareCollector 已安装软件采集器
type SoftwareCollector struct{}

func NewSoftwareCollector() *SoftwareCollector {
	return &SoftwareCollector{}
}

func (sc *SoftwareCollector) Name() string {
	return "software"
}

// SoftwareCollectionResult 软件采集结果
type SoftwareCollectionResult struct {
	Software []models.InstalledSoftwareItem `json:"software"`
	Total    int                             `json:"total"`
}

func (sc *SoftwareCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集已安装软件信息...")

	software, err := sc.collectPlatformSoftware(ctx)
	if err != nil {
		utils.LogError("Collector", "软件采集失败: %v", err)
		software = []models.InstalledSoftwareItem{}
	}

	utils.Info("Collector", "已安装软件采集完成: %d个软件", len(software))

	return &SoftwareCollectionResult{
		Software: software,
		Total:    len(software),
	}, nil
}
