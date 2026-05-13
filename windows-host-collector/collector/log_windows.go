//go:build windows

package collector

import (
	"context"
	"syscall"
	"unsafe"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"golang.org/x/sys/windows"
)

var (
	wevtapi                = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery           = wevtapi.NewProc("EvtQuery")
	procEvtNext            = wevtapi.NewProc("EvtNext")
	procEvtClose           = wevtapi.NewProc("EvtClose")
	procEvtRender          = wevtapi.NewProc("EvtRender")
	procEvtOpenChannelEnum = wevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath = wevtapi.NewProc("EvtNextChannelPath")
)

const (
	EvtQueryChannelPath       uint32 = 0x1
	EvtQueryReverseDirection  uint32 = 0x200
	EvtRenderEventXml         uint32 = 1
	ERROR_INSUFFICIENT_BUFFER uint32 = 122
	ERROR_NO_MORE_ITEMS       uint32 = 259
)

type evtHandle uintptr

func (h evtHandle) close() {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

func (lc *LogCollector) collectPlatformLogs(ctx context.Context) []models.WindowsLogItem {
	// 枚举本机所有事件通道
	sources := listAllChannels()
	if len(sources) == 0 {
		// 兜底：最常见的四个
		sources = []string{"Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational"}
	}

	// 过滤掉大多数字面上属于 Analytic/Debug/Trace/Diagnostic/Performance 的通道。
	// 这些日志在绝大多数系统上默认未启用，即便枚举得到，直接查询常返回
	// ERROR_NOT_SUPPORTED（50）。为减少无意义的报错，这里默认跳过。
	// 仍保留常见基础日志与 PowerShell/Operational。
	filtered := make([]string, 0, len(sources))
	for _, ch := range sources {
		if shouldKeepChannel(ch) {
			filtered = append(filtered, ch)
		}
	}

	state := newEventLogProgressState(defaultEventLogLimits(), len(filtered))
	var allLogs []models.WindowsLogItem

	for _, source := range filtered {
		select {
		case <-ctx.Done():
			return allLogs
		default:
		}

		logs := lc.readEvtLog(ctx, source, state)
		allLogs = append(allLogs, logs...)

		select {
		case <-ctx.Done():
			return allLogs
		default:
		}

		state.ChannelsDone++
		state.ChannelEvents = 0

		if state.ShouldReportProgress() {
			lc.reportEventLogProgress(source, state)
		}
	}

	return allLogs
}

// listAllChannels 使用 wevtapi 枚举本机全部事件通道
func listAllChannels() []string {
	h, _, err := procEvtOpenChannelEnum.Call(0, 0)
	if h == 0 {
		utils.LogError("Collector", "打开通道枚举失败: %v", err)
		return nil
	}
	eh := evtHandle(h)
	defer eh.close()

	var channels []string
	for {
		var needed uint32
		r1, _, e1 := procEvtNextChannelPath.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)))
		if r1 != 0 {
			// 不太可能在 0 缓冲时成功，保险处理直接继续
			continue
		}
		if errno, ok := e1.(syscall.Errno); ok {
			if uint32(errno) == ERROR_NO_MORE_ITEMS {
				break
			}
			if uint32(errno) == ERROR_INSUFFICIENT_BUFFER && needed > 0 {
				buf := make([]uint16, needed)
				r2, _, e2 := procEvtNextChannelPath.Call(uintptr(h), uintptr(needed), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&needed)))
				if r2 == 0 {
					// 读取失败，跳过本项
					_ = e2
					continue
				}
				ch := windows.UTF16ToString(buf)
				if ch != "" {
					channels = append(channels, ch)
				}
				continue
			}
		}
		// 其他错误，结束
		break
	}
	return channels
}

func (lc *LogCollector) readEvtLog(ctx context.Context, channelPath string, state *eventLogProgressState) []models.WindowsLogItem {
	channelPathUTF16, err := windows.UTF16PtrFromString(channelPath)
	if err != nil {
		utils.LogError("Collector", "通道名编码失败 %s: %v", channelPath, err)
		return nil
	}

	// 反向（新到旧）查询该通道
	query, _ := windows.UTF16PtrFromString("*")
	handle, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPathUTF16)),
		uintptr(unsafe.Pointer(query)),
		uintptr(EvtQueryChannelPath|EvtQueryReverseDirection),
	)
	if handle == 0 {
		utils.LogError("Collector", "查询事件日志 %s 失败: %v", channelPath, callErr)
		return nil
	}
	h := evtHandle(handle)
	defer h.close()

	logType := normalizeLogType(channelPath)
	var results []models.WindowsLogItem
	var idx int

	for {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		var ev evtHandle
		var returned uint32
		r1, _, e1 := procEvtNext.Call(
			handle,
			1,
			uintptr(unsafe.Pointer(&ev)),
			0,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r1 == 0 {
			if errno, ok := e1.(syscall.Errno); ok {
				if uint32(errno) == ERROR_NO_MORE_ITEMS {
					break
				}
			}
			// 其他错误：退出本通道
			break
		}

		state.RecordFetchedEvent()
		if state.ShouldReportProgress() {
			lc.reportEventLogProgress(channelPath, state)
		}

		// 渲染为 XML
		xmlStr := lc.renderEventXML(ev)
		ev.close()
		if xmlStr == "" {
			continue
		}

		if entry := parseEventXML(xmlStr, logType, idx); entry != nil {
			keep, stop := eventLogWindowDecision(lc.windowStart, entry)
			if stop {
				break
			}
			if keep {
				results = append(results, *entry)
				idx++
			}
		}
	}
	return results
}

func (lc *LogCollector) reportEventLogProgress(channel string, state *eventLogProgressState) {
	utils.Info("Collector", "事件日志采集进度: channels=%d/%d channel_events=%d total_events=%d", state.ChannelsDone, state.ChannelsTotal, state.ChannelEvents, state.TotalEvents)
	lc.report(LogProgress{
		Channel:       channel,
		ChannelsDone:  state.ChannelsDone,
		ChannelsTotal: state.ChannelsTotal,
		EventsRead:    state.ChannelEvents,
		TotalEvents:   state.TotalEvents,
	})
	state.MarkReported()
}

func (lc *LogCollector) renderEventXML(ev evtHandle) string {
	var bufUsed, propCount uint32
	// 首次调用获取所需缓冲区
	r1, _, e1 := procEvtRender.Call(
		0,
		uintptr(ev),
		uintptr(EvtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); !ok || uint32(errno) != ERROR_INSUFFICIENT_BUFFER {
			return ""
		}
	}

	// 第二次分配缓冲并渲染
	if bufUsed == 0 {
		return ""
	}
	buf := make([]uint16, bufUsed/2)
	r2, _, _ := procEvtRender.Call(
		0,
		uintptr(ev),
		uintptr(EvtRenderEventXml),
		uintptr(bufUsed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if r2 == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
