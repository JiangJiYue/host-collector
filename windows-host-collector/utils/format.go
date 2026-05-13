package utils

import (
	"fmt"
	"time"
)

// FormatTime 格式化时间为标准格式
func FormatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// FormatTimeRFC3339 格式化时间为RFC3339格式
func FormatTimeRFC3339(t time.Time) string {
	return t.Format(time.RFC3339)
}

// FormatBytes 格式化字节数为可读格式
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatGB 将字节数转换为GB，保留一位小数
func FormatGB(bytes uint64) float64 {
	return Round1(float64(bytes) / (1024 * 1024 * 1024))
}

// Round1 保留一位小数
func Round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

// StringPtr 返回字符串指针
func StringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// IntPtr 返回整数指针
func IntPtr(i int) *int {
	return &i
}

// BoolPtr 返回布尔指针
func BoolPtr(b bool) *bool {
	return &b
}

// FormatTimeUnix 格式化 Unix 毫秒时间戳
func FormatTimeUnix(ms int64) string {
	return time.Unix(ms/1000, 0).Format("2006-01-02 15:04:05")
}
