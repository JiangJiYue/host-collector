package timeline

import (
	"fmt"

	"collector-shared/contracts"
	"linux-host-collector/internal/collectors/logs"
	"linux-host-collector/internal/collectors/network"
	"linux-host-collector/internal/collectors/process"
	"linux-host-collector/internal/collectors/startup"
)

type Inputs struct {
	CollectedAt      string
	LogEvents        []logs.Event
	PersistenceItems []startup.PersistenceItem
	Network          network.Result
	Processes        []process.Process
}

func Derive(inputs Inputs) []contracts.TimelineEvent {
	events := make([]contracts.TimelineEvent, 0, len(inputs.LogEvents)+len(inputs.PersistenceItems)+len(inputs.Network.Connections)+len(inputs.Processes))

	for index, event := range inputs.LogEvents {
		timestamp, timestampSource := event.Timestamp, "log_event"
		if timestamp == "" {
			timestamp, timestampSource = inputs.CollectedAt, "collected_at"
		}
		events = append(events, contracts.TimelineEvent{
			ID:        fmt.Sprintf("linux-log-%d", index),
			Timestamp: timestamp,
			EventType: "linux.log." + event.EventType,
			Subject:   logSubject(event),
			PlatformExtensions: contracts.PlatformExtensions{Linux: map[string]any{
				"source":          event.Source,
				"program":         event.Program,
				"target":          event.Target,
				"remoteIp":        event.RemoteIP,
				"evidence":        event.Evidence,
				"timestampSource": timestampSource,
			}},
		})
	}

	for index, connection := range inputs.Network.Connections {
		if !connection.Listen {
			continue
		}
		events = append(events, contracts.TimelineEvent{
			ID:        fmt.Sprintf("linux-network-listen-%d", index),
			Timestamp: inputs.CollectedAt,
			EventType: "linux.network.listen",
			Subject: contracts.Subject{
				Type: contracts.SubjectNetwork,
				ID:   fmt.Sprintf("%s:%s:%d", connection.Protocol, connection.LocalAddress, connection.LocalPort),
			},
			PlatformExtensions: contracts.PlatformExtensions{Linux: map[string]any{
				"state":           connection.State,
				"inode":           connection.Inode,
				"timestampSource": "collected_at",
			}},
		})
	}

	for index, item := range inputs.PersistenceItems {
		events = append(events, contracts.TimelineEvent{
			ID:        fmt.Sprintf("linux-persistence-%d", index),
			Timestamp: inputs.CollectedAt,
			EventType: "linux.persistence." + item.Kind,
			Subject: contracts.Subject{
				Type: contracts.SubjectFile,
				ID:   item.Source,
				Name: item.Name,
			},
			PlatformExtensions: contracts.PlatformExtensions{Linux: map[string]any{
				"command":         item.Command,
				"timestampSource": "collected_at",
			}},
		})
	}

	for _, proc := range inputs.Processes {
		timestamp, timestampSource := proc.CreatedAt, "process_created_at"
		if timestamp == "" {
			timestamp, timestampSource = proc.CreateTime, "process_create_time"
		}
		if timestamp == "" {
			timestamp, timestampSource = inputs.CollectedAt, "collected_at"
		}
		events = append(events, contracts.TimelineEvent{
			ID:        fmt.Sprintf("linux-process-%d", proc.PID),
			Timestamp: timestamp,
			EventType: "linux.process.observed",
			Subject: contracts.Subject{
				Type: contracts.SubjectProcess,
				ID:   fmt.Sprintf("pid:%d", proc.PID),
				Name: proc.Name,
			},
			PlatformExtensions: contracts.PlatformExtensions{Linux: map[string]any{
				"ppid":            proc.PPID,
				"uid":             proc.UID,
				"commandLine":     proc.CommandLine,
				"timestampSource": timestampSource,
			}},
		})
	}

	return events
}

func logSubject(event logs.Event) contracts.Subject {
	if event.Actor != "" {
		return contracts.Subject{Type: contracts.SubjectUser, ID: "user:" + event.Actor, Name: event.Actor}
	}
	if event.Program != "" {
		return contracts.Subject{Type: contracts.SubjectProcess, ID: "program:" + event.Program, Name: event.Program}
	}
	return contracts.Subject{Type: contracts.SubjectHost, ID: "host"}
}
