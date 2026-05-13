package appcore

import (
	"fmt"
	"io"
)

type ConsoleStatusSink struct {
	writer io.Writer
}

func NewConsoleStatusSink(writer io.Writer) ConsoleStatusSink {
	return ConsoleStatusSink{writer: writer}
}

func (s ConsoleStatusSink) EmitStatus(event StatusEvent) {
	if s.writer == nil {
		return
	}
	fmt.Fprintln(s.writer, FormatStatusEvent(event))
}

func FormatStatusEvent(event StatusEvent) string {
	label := statusStateLabel(event.State)
	if label == "" {
		label = eventTypeLabel(event.Type)
	}
	text := event.Message
	if text == "" {
		text = event.StageName
	}
	if text == "" {
		text = event.StageKey
	}
	if event.Current > 0 || event.Total > 0 {
		text = fmt.Sprintf("%s (%d/%d)", text, event.Current, event.Total)
	}
	if event.Detail != "" {
		text = fmt.Sprintf("%s - %s", text, event.Detail)
	}
	if text == "" {
		text = string(event.Type)
	}
	return fmt.Sprintf("[%s] %s", label, text)
}

func statusStateLabel(state StatusState) string {
	switch state {
	case StatePending:
		return "等待"
	case StateRunning:
		return "运行中"
	case StateCompleted:
		return "完成"
	case StateSkipped:
		return "跳过"
	case StateFailed:
		return "失败"
	case StateDenied:
		return "拒绝"
	case StateDegraded:
		return "降级"
	default:
		return ""
	}
}

func eventTypeLabel(eventType EventType) string {
	switch eventType {
	case EventScanCompleted:
		return "完成"
	case EventScanFailed:
		return "失败"
	default:
		return "信息"
	}
}
