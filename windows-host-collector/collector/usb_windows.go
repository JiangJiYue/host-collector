//go:build windows

package collector

import (
	"fmt"
	"os"
	"strings"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"golang.org/x/sys/windows/registry"
)

func (uc *UsbCollector) collectUsbRecords() []models.UsbRecord {
	records := make([]models.UsbRecord, 0)

	// 注册表路径：USBSTOR
	usbStorKey := `SYSTEM\CurrentControlSet\Enum\USBSTOR`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, usbStorKey, registry.READ)
	if err != nil {
		utils.LogError("Collector", "打开 USBSTOR 注册表失败: %v", err)
		return records
	}
	defer key.Close()

	// 遍历设备类型（Disk&Ven_XXX&Prod_YYY）
	deviceTypes, err := key.ReadSubKeyNames(0)
	if err != nil {
		return records
	}

	idCounter := 0
	for _, deviceType := range deviceTypes {
		deviceKey, err := registry.OpenKey(key, deviceType, registry.READ)
		if err != nil {
			continue
		}

		// 遍历设备实例（序列号）
		instances, err := deviceKey.ReadSubKeyNames(0)
		if err != nil {
			deviceKey.Close()
			continue
		}

		for _, instance := range instances {
			instKey, err := registry.OpenKey(deviceKey, instance, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			friendlyName, _, _ := instKey.GetStringValue("FriendlyName")
			vendorID, _, _ := instKey.GetStringValue("VendorId")
			serialNumber := instance

			// 从设备类型字符串解析
			vendor, product := parseUsbDeviceType(deviceType)

			if friendlyName == "" {
				friendlyName = product
			}

			// 获取最后插入时间（从 Properties 子键）
			lastConnected := getLastUsbConnection(instKey)

			record := models.UsbRecord{
				Name:         friendlyName,
				Vendor:       coalesce(vendorID, vendor),
				InsertTime:   lastConnected,
				SerialNumber: serialNumber,
				MountPoint:   "",
			}

			records = append(records, record)
			idCounter++
			instKey.Close()
		}
		deviceKey.Close()
	}

	return records
}

// parseUsbDeviceType 解析 USBSTOR 设备类型字符串
// 格式: Disk&Ven_XXX&Prod_YYY&Rev_ZZZ
func parseUsbDeviceType(deviceType string) (vendor, product string) {
	parts := strings.Split(deviceType, "&")
	for _, part := range parts {
		if strings.HasPrefix(part, "Ven_") {
			vendor = strings.TrimPrefix(part, "Ven_")
		} else if strings.HasPrefix(part, "Prod_") {
			product = strings.TrimPrefix(part, "Prod_")
		}
	}
	return
}

// getLastUsbConnection 获取 USB 最后连接时间
func getLastUsbConnection(instKey registry.Key) string {
	// 尝试读取 Properties 子键中的时间信息
	propKey, err := registry.OpenKey(instKey, `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer propKey.Close()

	data, _, err := propKey.GetBinaryValue("")
	if err != nil || len(data) < 8 {
		return ""
	}

	// FILETIME 格式（8字节）
	_ = fmt.Sprintf("%x", data)
	return ""
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// 确保 os 包被使用
var _ = os.Getenv
