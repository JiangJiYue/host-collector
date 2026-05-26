package timeline

import (
	"testing"

	"linux-host-collector/internal/collectors/logs"
	"linux-host-collector/internal/collectors/network"
	"linux-host-collector/internal/collectors/process"
	"linux-host-collector/internal/collectors/startup"
)

func TestDeriveBuildsTimelineEventsFromCollectedSections(t *testing.T) {
	events := Derive(Inputs{
		CollectedAt: "2026-05-03T10:00:00Z",
		LogEvents: []logs.Event{
			{EventType: "auth_success", Source: "var/log/auth.log", Program: "sshd", Actor: "alice", Evidence: "10.0.0.8", Timestamp: "2026-05-03T09:59:01Z"},
		},
		PersistenceItems: []startup.PersistenceItem{
			{Kind: "systemd_service", Name: "evil.service", Source: "etc/systemd/system/evil.service", Command: "/bin/sh"},
		},
		Network: network.Result{Connections: []network.Connection{
			{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8080, State: "LISTEN", Listen: true, Inode: "12345"},
			{Protocol: "tcp", LocalAddress: "10.0.0.2", LocalPort: 80, State: "ESTABLISHED", Inode: "67890"},
		}},
		Processes: []process.Process{
			{PID: 1, Name: "init", CommandLine: "/sbin/init"},
		},
	})

	if len(events) != 4 {
		t.Fatalf("expected four timeline events, got %#v", events)
	}
	if events[0].EventType != "linux.log.auth_success" || events[0].Subject.Type != "user" || events[0].Subject.ID != "user:alice" {
		t.Fatalf("unexpected log timeline event: %#v", events[0])
	}
	if events[1].EventType != "linux.network.listen" || events[1].Subject.Type != "network" || events[1].Subject.ID != "tcp:127.0.0.1:8080" {
		t.Fatalf("unexpected network timeline event: %#v", events[1])
	}
	if events[2].EventType != "linux.persistence.systemd_service" || events[2].Subject.Type != "file" || events[2].Subject.ID != "etc/systemd/system/evil.service" {
		t.Fatalf("unexpected persistence timeline event: %#v", events[2])
	}
	if events[3].EventType != "linux.process.observed" || events[3].Subject.Type != "process" || events[3].Subject.ID != "pid:1" {
		t.Fatalf("unexpected process timeline event: %#v", events[3])
	}
	if events[0].Timestamp != "2026-05-03T09:59:01Z" {
		t.Fatalf("expected log original timestamp, got %#v", events[0])
	}
	if events[0].PlatformExtensions.Linux["timestampSource"] != "log_event" {
		t.Fatalf("expected log timestamp source, got %#v", events[0])
	}
	for _, event := range events[1:] {
		if event.Timestamp != "2026-05-03T10:00:00Z" {
			t.Fatalf("expected collectedAt timestamp, got %#v", event)
		}
		if event.PlatformExtensions.Linux["timestampSource"] != "collected_at" {
			t.Fatalf("expected collectedAt timestamp source, got %#v", event)
		}
	}
}

func TestDeriveSkipsEmptyInputs(t *testing.T) {
	events := Derive(Inputs{CollectedAt: "2026-05-03T10:00:00Z"})
	if len(events) != 0 {
		t.Fatalf("expected no timeline events, got %#v", events)
	}
}
