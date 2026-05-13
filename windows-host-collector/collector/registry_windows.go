//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"golang.org/x/sys/windows/registry"
)

var rootKeys = map[string]registry.Key{
	"HKEY_CLASSES_ROOT":   registry.CLASSES_ROOT,
	"HKEY_CURRENT_USER":   registry.CURRENT_USER,
	"HKEY_LOCAL_MACHINE":  registry.LOCAL_MACHINE,
	"HKEY_USERS":          registry.USERS,
	"HKEY_CURRENT_CONFIG": registry.CURRENT_CONFIG,
}

// collectAllRoots 采集高价值注册表取证路径，避免默认递归遍历全量 5 大根键。
func (rc *RegistryCollector) collectAllRoots(ctx context.Context) []models.RegistryValue {
	var allValues []models.RegistryValue
	plan := defaultTargetedRegistryPlan()

	for idx, target := range plan {
		state := newRegistryProgressState(target.Root+"\\"+target.Path, idx, len(plan), rc.progressEvery)
		rc.report(RegistryProgress{
			RootName:   state.RootName,
			RootsDone:  state.RootsDone,
			RootsTotal: state.RootsTotal,
			ValuesRead: state.ValuesRead,
		})
		utils.Info("Collector", "开始采集注册表目标: %s\\%s", target.Root, target.Path)
		values := rc.collectRegistryTarget(ctx, target, state)
		allValues = append(allValues, values...)
		utils.Info("Collector", "注册表目标 %s\\%s 采集完成: %d个值", target.Root, target.Path, len(values))
	}

	return allValues
}

func (rc *RegistryCollector) collectRegistryTarget(ctx context.Context, target RegistryTarget, state *registryProgressState) []models.RegistryValue {
	rootKey, ok := rootKeys[target.Root]
	if !ok {
		return nil
	}

	key, err := registry.OpenKey(rootKey, target.Path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer key.Close()

	fullPath := target.Root
	if target.Path != "" {
		fullPath += "\\" + target.Path
	}

	if target.Recursive {
		return rc.walkRegistryKey(ctx, target, key, target.Path, 0, state)
	}
	return rc.readRegistryKeyValues(key, fullPath, target, state)
}

// walkRegistryKey 递归遍历注册表 key
func (rc *RegistryCollector) walkRegistryKey(ctx context.Context, target RegistryTarget, key registry.Key, subPath string, depth int, state *registryProgressState) []models.RegistryValue {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if depth > rc.maxDepth {
		return nil
	}

	fullPath := target.Root
	if subPath != "" {
		fullPath = target.Root + "\\" + subPath
	}

	values := rc.readRegistryKeyValues(key, fullPath, target, state)

	// 递归遍历子 key
	subKeys, err := key.ReadSubKeyNames(0)
	if err == nil {
		for _, subKeyName := range subKeys {
			if err := ctx.Err(); err != nil {
				return values
			}
			childKey, err := registry.OpenKey(key, subKeyName, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				continue
			}
			childPath := subKeyName
			if subPath != "" {
				childPath = subPath + "\\" + subKeyName
			}
			childValues := rc.walkRegistryKey(ctx, target, childKey, childPath, depth+1, state)
			values = append(values, childValues...)
			childKey.Close()
		}
	}

	return values
}

func (rc *RegistryCollector) readRegistryKeyValues(key registry.Key, fullPath string, target RegistryTarget, state *registryProgressState) []models.RegistryValue {
	names := target.ValueNames
	if len(names) == 0 {
		var err error
		names, err = key.ReadValueNames(0)
		if err != nil {
			return nil
		}
	}

	values := make([]models.RegistryValue, 0, len(names))
	for _, name := range names {
		val := rc.readValue(key, name, fullPath)
		if val == nil {
			continue
		}
		val.CollectionCategory = target.CollectionCategory
		val.RiskPurpose = target.RiskPurpose
		val.ReferencedPath = extractReferencedPathFromRegistryValue(*val)
		values = append(values, *val)
		state.ValuesRead++
		if state.ShouldReport() {
			rc.report(RegistryProgress{
				RootName:   state.RootName,
				RootsDone:  state.RootsDone,
				RootsTotal: state.RootsTotal,
				ValuesRead: state.ValuesRead,
			})
			state.MarkReported()
		}
	}
	return values
}

// readValue 读取单个注册表 value
func (rc *RegistryCollector) readValue(key registry.Key, name string, fullPath string) *models.RegistryValue {
	// 尝试字符串类型
	val, valType, err := key.GetStringValue(name)
	if err == nil {
		return &models.RegistryValue{
			Name: name,
			Type: getRegistryTypeName(valType),
			Data: val,
			Path: fullPath,
		}
	}

	// 尝试 DWORD
	dwordVal, _, err2 := key.GetIntegerValue(name)
	if err2 == nil {
		return &models.RegistryValue{
			Name: name,
			Type: "REG_DWORD",
			Data: fmt.Sprintf("0x%08x (%d)", dwordVal, dwordVal),
			Path: fullPath,
		}
	}

	// 尝试读取原始数据
	bufLen, _, err4 := key.GetValue(name, make([]byte, 65536))
	if err4 == nil {
		buf := make([]byte, bufLen)
		n, valType5, err5 := key.GetValue(name, buf)
		if err5 == nil {
			buf = buf[:n]
			typeName := getRegistryTypeName(valType5)
			data := rc.formatValueData(buf, valType5, typeName)
			return &models.RegistryValue{
				Name: name,
				Type: typeName,
				Data: data,
				Path: fullPath,
			}
		}
	}

	return nil
}

// formatValueData 根据类型格式化原始数据
func (rc *RegistryCollector) formatValueData(buf []byte, valType uint32, typeName string) string {
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		if len(buf) >= 2 {
			return utf16BytesToString(buf)
		}
		return string(buf)

	case registry.MULTI_SZ:
		if len(buf) >= 2 {
			str := utf16BytesToString(buf)
			parts := strings.Split(str, "\x00")
			return strings.Join(parts, "\\0")
		}
		return string(buf)

	case registry.DWORD:
		if len(buf) >= 4 {
			val := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
			return fmt.Sprintf("0x%08x (%d)", val, val)
		}
		return hex.EncodeToString(buf)

	case registry.QWORD:
		if len(buf) >= 8 {
			val := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
				uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
			return fmt.Sprintf("0x%016x (%d)", val, val)
		}
		return hex.EncodeToString(buf)

	default:
		return hex.EncodeToString(buf)
	}
}

// getRegistryTypeName 获取注册表类型名称
func getRegistryTypeName(regType uint32) string {
	switch regType {
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_UNKNOWN(%d)", regType)
	}
}

// utf16BytesToString 将 UTF-16LE 字节切片转为 Go 字符串
func utf16BytesToString(buf []byte) string {
	if len(buf) < 2 {
		return ""
	}
	u16 := make([]uint16, 0, len(buf)/2)
	for i := 0; i+1 < len(buf); i += 2 {
		u16 = append(u16, uint16(buf[i])|uint16(buf[i+1])<<8)
	}
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return syscall.UTF16ToString(u16)
}
