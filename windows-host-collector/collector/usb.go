package collector

import (
	"context"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// UsbCollector USB 设备记录采集器
type UsbCollector struct{}

func NewUsbCollector() *UsbCollector {
	return &UsbCollector{}
}

func (uc *UsbCollector) Name() string {
	return "usb"
}

// UsbCollectionResult USB 采集结果
type UsbCollectionResult struct {
	Records []models.UsbRecord `json:"records"`
	Total   int                `json:"total"`
}

func (uc *UsbCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集 USB 设备记录...")
	records := uc.collectUsbRecords()

	utils.Info("Collector", "USB 设备记录采集完成: %d个设备", len(records))

	return &UsbCollectionResult{
		Records: records,
		Total:   len(records),
	}, nil
}
